#include "x86.h"
#include "device.h"

extern TSS tss;
extern ProcessTable pcb[MAX_PCB_NUM];
extern int current;

extern int displayRow;
extern int displayCol;

void GProtectFaultHandle(struct StackFrame *sf);

void syscallHandle(struct StackFrame *sf);

void syscallWrite(struct StackFrame *sf);
void syscallPrint(struct StackFrame *sf);

void timerHandle(struct StackFrame *sf);


void syscallFork(struct StackFrame *sf);
void syscallSleep(struct StackFrame *sf);
void syscallExit(struct StackFrame *sf);
void syscallExec(struct StackFrame *sf);

void irqHandle(struct StackFrame *sf)
{ // pointer sf = esp
	/* Reassign segment register */
	asm volatile("movw %%ax, %%ds" ::"a"(KSEL(SEG_KDATA)));
	/*XXX Save esp to stackTop */
	uint32_t tmpStackTop = pcb[current].stackTop;
	pcb[current].prevStackTop = pcb[current].stackTop;
	pcb[current].stackTop = (uint32_t)sf;

	switch (sf->irq)
	{
	case -1:
		break;
	case 0xd:
		GProtectFaultHandle(sf);
		break;
	case 0x20:
		timerHandle(sf);
		break;
	case 0x80:
		syscallHandle(sf);
		break;
	default:
		assert(0);
	}
	/*XXX Recover stackTop */
	pcb[current].stackTop = tmpStackTop;
}

void GProtectFaultHandle(struct StackFrame *sf)
{
	assert(0);
	return;
}

void timerHandle(struct StackFrame *sf)
{
	// TODO

	int i;
	i = (current+1) % MAX_PCB_NUM;
    //遍历所有pcb 为阻塞状态的进程减少sleep时间 sleep时间为0将进程状态设置为可运行
	for (; i != current; i = (i + 1) % MAX_PCB_NUM)
	{
		if (pcb[i].state == STATE_BLOCKED)
		{
			if (pcb[i].sleepTime > 0)
				pcb[i].sleepTime--;
			if (pcb[i].sleepTime == 0)
				pcb[i].state = STATE_RUNNABLE;
		}
	}
    // 当前进程时间片未用完则继续执行当前进程
	if (pcb[current].timeCount < MAX_TIME_COUNT)
	{
		pcb[current].timeCount++;
		return;
	}
	//否则将当前进程设置为可运行状态，并寻找下一个可运行的进程进行切换
	else 
	{
		pcb[current].state = STATE_RUNNABLE;
		pcb[current].timeCount = 0;
		for (i = (current + 1) % MAX_PCB_NUM; i != current; i = (i + 1) % MAX_PCB_NUM)
		{
			//忽略IDLE进程
			if (i == 0)
				continue;
			if (pcb[i].state == STATE_RUNNABLE)
				break;
		}
		pcb[i].state = STATE_RUNNING;

		//恢复选定进程的栈顶指针
		current = i;

		asm volatile("movl %0, %%esp"::"m"(pcb[current].stackTop));
		pcb[current].stackTop = pcb[current].prevStackTop;
        // 设置tss支持用户程序
		tss.esp0 = pcb[i].stackTop;
		//数据段选择子GDT
		tss.ss0 = KSEL(SEG_KDATA);
		//切换内核栈
		asm volatile("popl %gs");
		asm volatile("popl %fs");
		asm volatile("popl %es");
		asm volatile("popl %ds");
		asm volatile("popal");
		asm volatile("addl $8, %esp");
		asm volatile("iret");
	}
}

void syscallHandle(struct StackFrame *sf)
{
	switch (sf->eax)
	{ // syscall number
	case 0:
		syscallWrite(sf);
		break; // for SYS_WRITE
	case 1:
		syscallFork(sf);
		break; // for SYS_FORK
	case 2:
		syscallExec(sf);
		break; // for SYS_EXEC
	case 3:
		syscallSleep(sf);
		break; // for SYS_SLEEP
	case 4:
		syscallExit(sf);
		break; // for SYS_EXIT

	/*TODO Add Fork,Sleep... */
	default:
		break;
	}
}

void syscallWrite(struct StackFrame *sf)
{
	switch (sf->ecx)
	{ // file descriptor
	case 0:
		syscallPrint(sf);
		break; // for STD_OUT
	default:
		break;
	}
}

void syscallPrint(struct StackFrame *sf)
{
	int sel = sf->ds; // segment selector for user data, need further modification
	char *str = (char *)sf->edx;
	int size = sf->ebx;
	int i = 0;
	int pos = 0;
	char character = 0;
	uint16_t data = 0;
	asm volatile("movw %0, %%es" ::"m"(sel));
	for (i = 0; i < size; i++)
	{
		asm volatile("movb %%es:(%1), %0" : "=r"(character) : "r"(str + i));
		if (character == '\n')
		{
			displayRow++;
			displayCol = 0;
			if (displayRow == 25)
			{
				displayRow = 24;
				displayCol = 0;
				scrollScreen();
			}
		}
		else
		{
			data = character | (0x0c << 8);
			pos = (80 * displayRow + displayCol) * 2;
			asm volatile("movw %0, (%1)" ::"r"(data), "r"(pos + 0xb8000));
			displayCol++;
			if (displayCol == 80)
			{
				displayRow++;
				displayCol = 0;
				if (displayRow == 25)
				{
					displayRow = 24;
					displayCol = 0;
					scrollScreen();
				}
			}
		}
		// asm volatile("int $0x20"); //XXX Testing irqTimer during syscall
		// asm volatile("int $0x20":::"memory"); //XXX Testing irqTimer during syscall
	}

	updateCursor(displayRow, displayCol);
	// take care of return value
	return;
}

// TODO syscallFork ...
void syscallFork(struct StackFrame *sf)
 {
    //找到一个空闲的PCB
	int i, j;
	for (i = 0; i < MAX_PCB_NUM; i++)
	 {
		if (pcb[i].state == STATE_DEAD)
			break;
	}
	if (i != MAX_PCB_NUM) 
	{
		//开启中断
		enableInterrupt();
		//复制用户空间
		for (j = 0; j < 0x100000; j++)
		 {
			*(uint8_t *)(j + (i+1)*0x100000) = *(uint8_t *)(j + (current+1)*0x100000);
		}
		//关闭中断
		disableInterrupt();
		//设置新的PCB的值
		pcb[i].pid = i;
		pcb[i].timeCount = 0;
		pcb[i].sleepTime = pcb[current].sleepTime;
		pcb[i].prevStackTop = (uint32_t)&(pcb[i].stackTop);
		pcb[i].stackTop = (uint32_t)&(pcb[i].regs);
		pcb[i].state = STATE_RUNNABLE;
		//设置寄存器值
		pcb[i].regs.cs = USEL(2*i + 1);
		pcb[i].regs.ds = USEL(2*i + 2);
		pcb[i].regs.es = USEL(2*i + 2);
		pcb[i].regs.fs = USEL(2*i + 2);
		pcb[i].regs.ss = USEL(2*i + 2);
		pcb[i].regs.eflags = pcb[current].regs.eflags;
		pcb[i].regs.edx = pcb[current].regs.edx;
		pcb[i].regs.ecx = pcb[current].regs.ecx;
		pcb[i].regs.ebx = pcb[current].regs.ebx;
		pcb[i].regs.esp = pcb[current].regs.esp;
		pcb[i].regs.ebp = pcb[current].regs.ebp;
		pcb[i].regs.edi = pcb[current].regs.edi;
		pcb[i].regs.esi = pcb[current].regs.esi;
		pcb[i].regs.eip = pcb[current].regs.eip;
		//设置返回值，子进程返回0 父进程返回子进程ID
		pcb[i].regs.eax = 0;
		pcb[current].regs.eax = i;
	}
	else 
	{
		//没有PCB空就返回-1
		pcb[current].regs.eax = -1;
	}
	return;
}

void syscallSleep(struct StackFrame *sf)
 {
	//设置当前进程的sleep并改变状态为阻塞
	pcb[current].sleepTime = sf->ecx;
	pcb[current].state = STATE_BLOCKED;

	int i = (current + 1) % MAX_PCB_NUM;
	//寻找下一个可运行的进程同上
	for (; i != current; i = (i + 1) % MAX_PCB_NUM)
	{
		if (i == 0)
			continue;
		if (pcb[i].state == STATE_RUNNABLE)
			break;
	}
	//如果没有可运行的用户程序 选择内核进程
	if (i == current)
		i = 0;
	pcb[i].state = STATE_RUNNING;
	
	//同上
	current = i;
	asm volatile("movl %0, %%esp"::"m"(pcb[current].stackTop));
	pcb[current].stackTop = pcb[current].prevStackTop;
	tss.esp0 = pcb[i].stackTop;
	tss.ss0 = KSEL(SEG_KDATA);
	asm volatile("popl %gs");
	asm volatile("popl %fs");
	asm volatile("popl %es");
	asm volatile("popl %ds");
	asm volatile("popal");
	asm volatile("addl $8, %esp");
	asm volatile("iret");
}

void syscallExit(struct StackFrame *sf) 
{
	pcb[current].state = STATE_DEAD;

	//同上
	int i = (current + 1) % MAX_PCB_NUM;

	for (; i != current; i = (i + 1) % MAX_PCB_NUM)
	{
		if (i == 0)
			continue;
		if (pcb[i].state == STATE_RUNNABLE)
			break;
	}

	if (i == current)
		i = 0;
	pcb[i].state = STATE_RUNNING;
	current = i;
	
	asm volatile("movl %0, %%esp"::"m"(pcb[current].stackTop));
	pcb[current].stackTop = pcb[current].prevStackTop;
	tss.esp0 = pcb[i].stackTop;
	tss.ss0 = KSEL(SEG_KDATA);
	asm volatile("popl %gs");
	asm volatile("popl %fs");
	asm volatile("popl %es");
	asm volatile("popl %ds");
	asm volatile("popal");
	asm volatile("addl $8, %esp");
	asm volatile("iret");
}

void syscallExec(struct StackFrame *sf)
{
	return;
}