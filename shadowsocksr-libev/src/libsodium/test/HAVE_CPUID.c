
void main(){
	unsigned int cpu_info[4];
	__asm__ __volatile__ ("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1" :
	"=a" (cpu_info[0]), "=&r" (cpu_info[1]),
	"=c" (cpu_info[2]), "=d" (cpu_info[3]) :
	"0" (0U), "2" (0U));
}