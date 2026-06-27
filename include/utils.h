#ifndef UTILS_H
# define UTILS_H

const char  *scan_type_to_str(int scan_type);
const char  *result_to_str(int result);
void    print_usage(void);
uint16_t    checksum(void *data, int len);


#endif
