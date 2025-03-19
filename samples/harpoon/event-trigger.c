#include <unistd.h>
#include <linux/unistd.h>

int main(void)
{
	return syscall(__NR_dup, 1);
}
