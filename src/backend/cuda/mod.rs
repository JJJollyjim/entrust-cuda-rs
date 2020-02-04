mod ext;
use crossbeam::{channel, thread};
use ext::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nvml_wrapper::{enum_wrappers::device::TemperatureSensor, NVML};
use rustacuda::{device::DeviceAttribute, launch, memory::DeviceCopy, module::Symbol, prelude::*};
use std::{error::Error, ffi::CString, time::Duration};

use crate::{Crack, MAX_CODE};

const THREADS: u32 = 512;
const BLOCK_SIZE: u32 = 100;
const CHUNK_SIZE: u32 = THREADS * BLOCK_SIZE;

const MAX_PAYLOAD_SIZE: usize = 1024;

/// This is a newtype extension of the impls rustacuda provides for [T; 1..=32]
struct PaddedPayload([u8; MAX_PAYLOAD_SIZE]);

unsafe impl DeviceCopy for PaddedPayload {}

fn run_on_device(
    device: Device,
    // The parameters of the cracking attempt
    salt: &[u8; 8],
    correct_mac: &[u8; 12],
    payload: &PaddedPayload,
    payload_len: usize,
    // Control stuff
    work_rx: channel::Receiver<u32>,
    did_work: impl Fn(u32),
    pls_stop: channel::Receiver<()>,
) -> Result<Option<u32>, Box<dyn Error + Send + Sync>> {
    // Create a context associated to this device
    let _context =
        Context::create_and_push(ContextFlags::MAP_HOST | ContextFlags::SCHED_AUTO, device)?;

    // Load the module containing the function we want to call
    let module_data = CString::new(include_str!(env!("ENTRUST_KERNEL_PTX")))?;
    let module = Module::load_from_string(&module_data)?;

    let max_data_size: usize = module.get_global(&CString::new("MAX_DATA_SIZE")?)?.read()?;
    // Unfortunately I don't see how to safely support a dynamic MAX_PAYLOAD_SIZE,
    // as rustacuda does not allow taking a DeviceSlice of a Symbol
    // (TODO try and add that functionality?)
    assert_eq!(max_data_size, MAX_PAYLOAD_SIZE);

    module
        .get_global(&CString::new("data")?)?
        .copy_from(payload)?;
    module
        .get_global(&CString::new("data_size")?)?
        .copy_from(&payload_len)?;
    module.get_global(&CString::new("salt")?)?.copy_from(salt)?;
    module
        .get_global(&CString::new("correctmac")?)?
        .copy_from(correct_mac)?;

    // The GPU will write the answer here when it finds it
    let answer_sym: Symbol<u32> = module.get_global(&CString::new("answer")?)?;

    // Create a stream to submit work to
    let stream = Stream::new(StreamFlags::NON_BLOCKING, None)?;

    while let Ok(chunk_base) = work_rx.try_recv() {
        // Launching kernels is unsafe since Rust can't enforce safety - think of kernel launches
        // as a foreign-function call. In this case, it is - this kernel is written in CUDA C.
        unsafe {
            launch!(module.kern<<<BLOCK_SIZE, THREADS, 0, stream>>>(
                chunk_base
            ))?;
        }

        // The kernel launch is asynchronous, so we wait for the kernel to finish executing
        stream.synchronize()?;

        did_work(CHUNK_SIZE.into());

        match answer_sym.read().unwrap() {
            0xFFFFFFFF => (),
            ans if ans > MAX_CODE => panic!("illegal answer read from GPU!"),
            answer => {
                return Ok(Some(answer));
            }
        }

        if pls_stop.is_full() {
            return Ok(None);
        }
    }

    Ok(None)
}

fn stats_thread(
    progresses_unord: &[ProgressBar],
    pcie_triples: &[(u32, u32, u32)],
    pls_stop: channel::Receiver<()>,
) -> Result<(), Box<dyn Error>> {
    let nvml = NVML::init()?;

    let mut devices = Vec::with_capacity(progresses_unord.len());

    for idx in 0..nvml.device_count()? {
        let device = nvml.device_by_index(idx)?;
        let pcie = device.pci_info()?;

        let progress = pcie_triples
            .iter()
            .zip(progresses_unord)
            .find(|(&want_pcie, _)| want_pcie == (pcie.domain, pcie.bus, pcie.device))
            .ok_or("no matching pci device")?
            .1;
        devices.push((device, progress));
    }

    loop {
        for (device, progress) in &devices {
            let temp = device.temperature(TemperatureSensor::Gpu)?;
            let util = device.utilization_rates()?.gpu;
            let power = device.power_usage()? / 1000;
            progress.set_message(&format!(
                " 🌡️ {:<2}°C  🖥️ {:<3}%  ⚡{:<3}W",
                temp, util, power
            ));

            if pls_stop.is_full() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub struct CudaBackend;
impl Crack for CudaBackend {
    fn hack(
        salt: [u8; 8],
        correct_mac: [u8; 12],
        payload: &[u8],
        progress: ProgressBar,
    ) -> Option<u32> {
        // Initialize the CUDA API
        rustacuda::init(CudaFlags::empty()).expect("couldn't initialize CUDA");

        let (work_tx, work_rx) = channel::unbounded();

        let multi = MultiProgress::new();

        // TODO unfuck
        for chunk_base in (976..)
            .map(|chunk_idx| chunk_idx * CHUNK_SIZE)
            .take_while(|&base| (base <= (MAX_CODE + CHUNK_SIZE)))
        {
            work_tx.send(chunk_base).unwrap();
        }

        let devs = Device::devices()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(devs.len() > 0);

        let pcie_triples = devs
            .iter()
            .map(|device| {
                (
                    device.get_attribute(DeviceAttribute::PciDomainId).unwrap() as u32,
                    device.get_attribute(DeviceAttribute::PciBusId).unwrap() as u32,
                    device.get_attribute(DeviceAttribute::PciDeviceId).unwrap() as u32,
                )
            })
            .collect::<Vec<_>>();

        let style = ProgressStyle::default_spinner()
            .template("{spinner} {prefix:.green} 🏃{per_sec} {msg}")
            .tick_strings(&["💥", "🔥", "😴"]);

        let dev_progresses = devs
            .iter()
            .enumerate()
            .map(|(idx, d)| {
                let bar = ProgressBar::new_spinner().with_style(style.clone());
                multi.add(bar.clone());
                bar.set_prefix(&format!("#{} {}", idx, d.name().unwrap()));
                bar
            })
            .collect::<Vec<_>>();

        multi.add(progress.clone());

        let (pls_stop_tx, pls_stop_rx) = channel::bounded(1);

        let mut padded_payload = PaddedPayload([0; MAX_PAYLOAD_SIZE]);
        assert!(payload.len() < MAX_PAYLOAD_SIZE, "HMAC payload would overflow the on-GPU buffer! If your token is really this big, increase MAC_DATA_SIZE in `main.cu` and MAX_PAYLOAD_SIZE in `src/backend/cuda/mod.rs`");
        padded_payload.0[0..payload.len()].copy_from_slice(payload);

        thread::scope(|s| {
            s.spawn(|_| {
                stats_thread(&dev_progresses, &pcie_triples, pls_stop_rx.clone()).unwrap();
            });

            let join_handles = devs
                .into_iter()
                .zip(&dev_progresses)
                .map(|(device, device_progress)| {
                    let rx = work_rx.clone();

                    // Shadow shared variables with references to them, so the move closure doesn't eat them
                    let progress = &progress;
                    let dev_progresses = &dev_progresses;
                    let pls_stop_rx = &pls_stop_rx;
                    let padded_payload = &padded_payload;

                    // TODO name all threads
                    s.spawn(move |_| {
                        let result = run_on_device(
                            device,
                            &salt,
                            &correct_mac,
                            &padded_payload,
                            payload.len(),
                            rx,
                            |done_size| {
                                device_progress.inc(done_size.into());
                                progress.inc(done_size.into());
                            },
                            pls_stop_rx.clone(),
                        )
                        .unwrap();

                        if result.is_some() {
                            // We need to stop all the progress bars, causing the main thread to join.
                            // Ideally a better API would exist on MultiProgress to do this
                            for device_progress in dev_progresses.iter() {
                                device_progress.abandon();
                            }
                            progress.finish();
                        } else {
                            device_progress.finish();
                        }

                        result
                    })
                })
                .collect::<Vec<_>>();

            progress.enable_steady_tick(100);

            multi.join().expect("couldn't join multi-progress");

            pls_stop_tx
                .send(())
                .expect("couldn't instruct threads to finish");

            join_handles
                .into_iter()
                .filter_map(|thread| thread.join().unwrap())
                .next()
        })
        .expect("couldn't join scope")
    }
}
