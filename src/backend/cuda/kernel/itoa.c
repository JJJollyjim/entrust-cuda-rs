__device__ void reverse(char str[], int length) {
  int start = 0;
  int end = length - 1;
  while (start < end) {
    char interm = *(str + start);
    *(str + start) = *(str + end);
    *(str + end) = interm;
    start++;
    end--;
  }
}

// Implementation of itoa()
__device__ int itoa(unsigned int num, char *str) {
  int i = 0;

  /* Handle 0 explicitely, otherwise empty string is printed for 0 */
  if (num == 0) {
    str[i++] = '0';
    /* str[i] = '\0'; */
    return i;
  }


  // Process individual digits
  while (num != 0) {
    int rem = num % 10;
    str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
    num = num / 10;
  }

  /* str[i] = '\0'; // Append string terminator */

  // Reverse the string
  reverse(str, i);

  return i;
}
