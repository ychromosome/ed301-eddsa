#include <stddef.h>

#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

unsigned int ed301_vg_running_on_valgrind(void)
{
    return RUNNING_ON_VALGRIND;
}

void ed301_vg_make_mem_undefined(void *address, size_t length)
{
    (void)VALGRIND_MAKE_MEM_UNDEFINED(address, length);
}

void ed301_vg_make_mem_defined(void *address, size_t length)
{
    (void)VALGRIND_MAKE_MEM_DEFINED(address, length);
}

unsigned int ed301_vg_get_vbits(
    const void *address,
    unsigned char *vbits,
    size_t length)
{
    return VALGRIND_GET_VBITS(address, vbits, length);
}

unsigned long ed301_vg_count_errors(void)
{
    return VALGRIND_COUNT_ERRORS;
}
