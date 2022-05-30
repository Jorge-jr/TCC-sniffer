	.arch armv5te
	.fpu softvfp
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 6
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
	.file	"sniffer2.c"
	.text
	.section	.rodata
	.align	2
.LC0:
	.ascii	"iw dev mon0 set channel %d\000"
	.align	2
.LC1:
	.ascii	"ifconfig wlan0 down\000"
	.align	2
.LC2:
	.ascii	"iwlist mon0 channel\000"
	.text
	.align	2
	.global	channel_hopper
	.syntax unified
	.arm
	.type	channel_hopper, %function
channel_hopper:
	@ args = 0, pretend = 0, frame = 32
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{fp, lr}
	add	fp, sp, #4
	sub	sp, sp, #32
	mov	r0, #0
	bl	time(PLT)
	mov	r3, r0
	mov	r0, r3
	bl	srand(PLT)
.L2:
	sub	r3, fp, #32
	ldr	r2, [fp, #-8]
	ldr	r1, .L3
.LPIC0:
	add	r1, pc, r1
	mov	r0, r3
	bl	sprintf(PLT)
	ldr	r3, .L3+4
.LPIC1:
	add	r3, pc, r3
	mov	r0, r3
	bl	system(PLT)
	mov	r0, #1
	bl	sleep(PLT)
	sub	r3, fp, #32
	mov	r0, r3
	bl	system(PLT)
	ldr	r3, .L3+8
.LPIC2:
	add	r3, pc, r3
	mov	r0, r3
	bl	system(PLT)
	mov	r0, #0
	bl	sleep(PLT)
	bl	rand(PLT)
	mov	r1, r0
	ldr	r3, .L3+12
	smull	r2, r3, r1, r3
	asr	r2, r3, #1
	asr	r3, r1, #31
	sub	r2, r2, r3
	mov	r3, r2
	lsl	r3, r3, #2
	add	r3, r3, r2
	lsl	r3, r3, #1
	add	r3, r3, r2
	sub	r2, r1, r3
	add	r3, r2, #1
	str	r3, [fp, #-8]
	b	.L2
.L4:
	.align	2
.L3:
	.word	.LC0-(.LPIC0+8)
	.word	.LC1-(.LPIC1+8)
	.word	.LC2-(.LPIC2+8)
	.word	780903145
	.size	channel_hopper, .-channel_hopper
	.section	.rodata
	.align	2
.LC3:
	.ascii	"next -> %d\012\000"
	.text
	.align	2
	.global	channel_hopper_incremental
	.syntax unified
	.arm
	.type	channel_hopper_incremental, %function
channel_hopper_incremental:
	@ args = 0, pretend = 0, frame = 32
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{fp, lr}
	add	fp, sp, #4
	sub	sp, sp, #32
.L8:
	mov	r3, #1
	str	r3, [fp, #-8]
	b	.L6
.L7:
	sub	r3, fp, #32
	ldr	r2, [fp, #-8]
	ldr	r1, .L9
.LPIC3:
	add	r1, pc, r1
	mov	r0, r3
	bl	sprintf(PLT)
	ldr	r3, .L9+4
.LPIC4:
	add	r3, pc, r3
	mov	r0, r3
	bl	system(PLT)
	mov	r0, #1
	bl	sleep(PLT)
	sub	r3, fp, #32
	mov	r0, r3
	bl	system(PLT)
	ldr	r3, .L9+8
.LPIC5:
	add	r3, pc, r3
	mov	r0, r3
	bl	system(PLT)
	mov	r0, #0
	bl	sleep(PLT)
	ldr	r1, [fp, #-8]
	ldr	r3, .L9+12
.LPIC6:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
.L6:
	ldr	r3, [fp, #-8]
	add	r2, r3, #1
	str	r2, [fp, #-8]
	cmp	r3, #0
	bne	.L7
	b	.L8
.L10:
	.align	2
.L9:
	.word	.LC0-(.LPIC3+8)
	.word	.LC1-(.LPIC4+8)
	.word	.LC2-(.LPIC5+8)
	.word	.LC3-(.LPIC6+8)
	.size	channel_hopper_incremental, .-channel_hopper_incremental
	.global	hopper
	.bss
	.align	2
	.type	hopper, %object
	.size	hopper, 4
hopper:
	.space	4
	.global	devices
	.align	2
	.type	devices, %object
	.size	devices, 4
devices:
	.space	4
	.global	sniffed_devices
	.align	2
	.type	sniffed_devices, %object
	.size	sniffed_devices, 4
sniffed_devices:
	.space	4
	.section	.rodata
	.align	2
.LC5:
	.ascii	"Monitoring interface: %s\012\000"
	.align	2
.LC6:
	.ascii	"ERRO: %s\012\000"
	.align	2
.LC7:
	.ascii	"pcap_datalink(): %s\012\000"
	.align	2
.LC8:
	.ascii	"Starting capture loop\000"
	.align	2
.LC9:
	.ascii	"%02x:%02x:%02x:%02x:%02x:%02x  -- count=%d\012\000"
	.align	2
.LC4:
	.ascii	"mon0\000"
	.text
	.align	2
	.global	main
	.syntax unified
	.arm
	.type	main, %function
main:
	@ args = 0, pretend = 0, frame = 32
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{r4, fp, lr}
	add	fp, sp, #8
	sub	sp, sp, #52
	str	r0, [fp, #-40]
	str	r1, [fp, #-44]
	mov	r3, #0
	ldr	r2, .L18
.LPIC7:
	add	r2, pc, r2
	mov	r1, #0
	ldr	r0, .L18+4
.LPIC8:
	add	r0, pc, r0
	bl	pthread_create(PLT)
	ldr	r2, .L18+8
.LPIC9:
	add	r2, pc, r2
	sub	r3, fp, #32
	ldm	r2, {r0, r1}
	str	r0, [r3]
	add	r3, r3, #4
	strb	r1, [r3]
	sub	r3, fp, #32
	mov	r1, r3
	ldr	r3, .L18+12
.LPIC10:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	sub	r0, fp, #32
	ldr	r3, [fp, #-16]
	str	r3, [sp]
	mov	r3, #0
	mov	r2, #1
	mov	r1, #8192
	bl	pcap_open_live(PLT)
	str	r0, [fp, #-20]
	ldr	r3, [fp, #-20]
	cmp	r3, #0
	bne	.L12
	ldr	r1, [fp, #-16]
	ldr	r3, .L18+16
.LPIC11:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
.L12:
	ldr	r0, [fp, #-20]
	bl	pcap_datalink(PLT)
	str	r0, [fp, #-24]
	ldr	r3, [fp, #-24]
	cmp	r3, #0
	bge	.L13
	ldr	r0, [fp, #-20]
	bl	pcap_geterr(PLT)
	mov	r3, r0
	mov	r1, r3
	ldr	r3, .L18+20
.LPIC12:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	mvn	r3, #0
	b	.L17
.L13:
	ldr	r3, .L18+24
.LPIC13:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	mov	r3, #0
	ldr	r2, .L18+28
.LPIC14:
	add	r2, pc, r2
	mov	r1, #0
	ldr	r0, [fp, #-20]
	bl	pcap_loop(PLT)
	mov	r0, #10
	bl	putchar(PLT)
	b	.L15
.L16:
	ldr	r3, .L18+32
.LPIC15:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldrb	r3, [r3]	@ zero_extendqisi2
	mov	ip, r3
	ldr	r3, .L18+36
.LPIC16:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldrb	r3, [r3, #1]	@ zero_extendqisi2
	mov	lr, r3
	ldr	r3, .L18+40
.LPIC17:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldrb	r3, [r3, #2]	@ zero_extendqisi2
	mov	r4, r3
	ldr	r3, .L18+44
.LPIC18:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldrb	r3, [r3, #3]	@ zero_extendqisi2
	mov	r2, r3
	ldr	r3, .L18+48
.LPIC19:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldrb	r3, [r3, #4]	@ zero_extendqisi2
	mov	r1, r3
	ldr	r3, .L18+52
.LPIC20:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldrb	r3, [r3, #5]	@ zero_extendqisi2
	mov	r0, r3
	ldr	r3, .L18+56
.LPIC21:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldr	r3, [r3, #8]
	str	r3, [sp, #12]
	str	r0, [sp, #8]
	str	r1, [sp, #4]
	str	r2, [sp]
	mov	r3, r4
	mov	r2, lr
	mov	r1, ip
	ldr	r0, .L18+60
.LPIC22:
	add	r0, pc, r0
	bl	printf(PLT)
	ldr	r3, .L18+64
.LPIC23:
	add	r3, pc, r3
	ldr	r3, [r3]
	ldr	r2, [r3, #12]
	ldr	r3, .L18+68
.LPIC24:
	add	r3, pc, r3
	str	r2, [r3]
.L15:
	ldr	r3, .L18+72
.LPIC25:
	add	r3, pc, r3
	ldr	r3, [r3]
	cmp	r3, #0
	bne	.L16
	mov	r3, #0
.L17:
	mov	r0, r3
	sub	sp, fp, #8
	@ sp needed
	pop	{r4, fp, pc}
.L19:
	.align	2
.L18:
	.word	channel_hopper_incremental-(.LPIC7+8)
	.word	hopper-(.LPIC8+8)
	.word	.LC4-(.LPIC9+8)
	.word	.LC5-(.LPIC10+8)
	.word	.LC6-(.LPIC11+8)
	.word	.LC7-(.LPIC12+8)
	.word	.LC8-(.LPIC13+8)
	.word	packetHandler-(.LPIC14+8)
	.word	devices-(.LPIC15+8)
	.word	devices-(.LPIC16+8)
	.word	devices-(.LPIC17+8)
	.word	devices-(.LPIC18+8)
	.word	devices-(.LPIC19+8)
	.word	devices-(.LPIC20+8)
	.word	devices-(.LPIC21+8)
	.word	.LC9-(.LPIC22+8)
	.word	devices-(.LPIC23+8)
	.word	devices-(.LPIC24+8)
	.word	devices-(.LPIC25+8)
	.size	main, .-main
	.section	.rodata
	.align	2
.LC10:
	.ascii	"Could not create socket\000"
	.align	2
.LC11:
	.ascii	"192.168.0.127\000"
	.align	2
.LC12:
	.ascii	"Not an ieee802.11 frame type!\000"
	.align	2
.LC13:
	.ascii	"connection error\000"
	.align	2
.LC14:
	.ascii	"connected\000"
	.align	2
.LC15:
	.ascii	"%02x:%02x:%02x:%02x:%02x:%02x %s %d \012\000"
	.align	2
.LC16:
	.ascii	"%s sended!\012\000"
	.align	2
.LC17:
	.ascii	"socket error %d -> %s\012\000"
	.align	2
.LC18:
	.ascii	"Erro -> %d\012\000"
	.text
	.align	2
	.global	packetHandler
	.syntax unified
	.arm
	.type	packetHandler, %function
packetHandler:
	@ args = 0, pretend = 0, frame = 104
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{r4, r5, fp, lr}
	add	fp, sp, #12
	sub	sp, sp, #128
	str	r0, [fp, #-104]
	str	r1, [fp, #-108]
	str	r2, [fp, #-112]
	mov	r3, #0
	str	r3, [fp, #-16]
	mov	r3, #0
	strb	r3, [fp, #-59]
	sub	r3, fp, #68
	mov	r1, #10
	mov	r0, r3
	bl	gethostname(PLT)
	mov	r2, #17
	mov	r1, #2
	mov	r0, #2
	bl	socket(PLT)
	str	r0, [fp, #-20]
	ldr	r3, [fp, #-20]
	cmn	r3, #1
	bne	.L21
	ldr	r3, .L34
.LPIC26:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
.L21:
	mov	r3, #16
	str	r3, [fp, #-24]
	mov	r3, #2
	strh	r3, [fp, #-84]	@ movhi
	ldr	r0, .L34+4
	bl	htons(PLT)
	mov	r3, r0
	strh	r3, [fp, #-82]	@ movhi
	ldr	r3, .L34+8
.LPIC27:
	add	r3, pc, r3
	mov	r0, r3
	bl	inet_addr(PLT)
	mov	r3, r0
	str	r3, [fp, #-80]
	ldr	r3, [fp, #-112]
	str	r3, [fp, #-28]
	ldr	r3, [fp, #-28]
	ldrh	r3, [r3, #2]
	mov	r2, r3
	ldr	r3, [fp, #-112]
	add	r3, r3, r2
	str	r3, [fp, #-32]
	ldr	r3, [fp, #-32]
	ldrb	r3, [r3]	@ zero_extendqisi2
	and	r3, r3, #12
	cmp	r3, #12
	bne	.L22
	ldr	r3, .L34+12
.LPIC28:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	b	.L23
.L22:
	ldr	r3, [fp, #-32]
	ldrb	r3, [r3]	@ zero_extendqisi2
	and	r3, r3, #12
	cmp	r3, #0
	bne	.L24
	ldr	r3, [fp, #-32]
	ldrb	r3, [r3]	@ zero_extendqisi2
	and	r3, r3, #240
	cmp	r3, #128
	bne	.L25
	mov	r3, #1
	str	r3, [fp, #-16]
.L25:
	ldr	r3, [fp, #-28]
	ldrh	r3, [r3, #2]
	mov	r2, r3
	ldr	r3, [fp, #-112]
	add	r3, r3, r2
	str	r3, [fp, #-52]
	sub	r3, fp, #84
	mov	r2, #16
	mov	r1, r3
	ldr	r0, [fp, #-20]
	bl	connect(PLT)
	mov	r3, r0
	cmp	r3, #0
	bge	.L26
	ldr	r3, .L34+16
.LPIC29:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	b	.L23
.L26:
	ldr	r3, .L34+20
.LPIC30:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	ldr	r3, [fp, #-52]
	ldrb	r3, [r3, #10]	@ zero_extendqisi2
	mov	r4, r3
	ldr	r3, [fp, #-52]
	ldrb	r3, [r3, #11]	@ zero_extendqisi2
	mov	r5, r3
	ldr	r3, [fp, #-52]
	ldrb	r3, [r3, #12]	@ zero_extendqisi2
	mov	r2, r3
	ldr	r3, [fp, #-52]
	ldrb	r3, [r3, #13]	@ zero_extendqisi2
	mov	r1, r3
	ldr	r3, [fp, #-52]
	ldrb	r3, [r3, #14]	@ zero_extendqisi2
	mov	ip, r3
	ldr	r3, [fp, #-52]
	ldrb	r3, [r3, #15]	@ zero_extendqisi2
	mov	lr, r3
	sub	r0, fp, #92
	ldr	r3, [fp, #-16]
	str	r3, [sp, #20]
	sub	r3, fp, #68
	str	r3, [sp, #16]
	str	lr, [sp, #12]
	str	ip, [sp, #8]
	str	r1, [sp, #4]
	str	r2, [sp]
	mov	r3, r5
	mov	r2, r4
	ldr	r1, .L34+24
.LPIC31:
	add	r1, pc, r1
	bl	sprintf(PLT)
	sub	r3, fp, #92
	mov	r0, r3
	bl	strlen(PLT)
	mov	r2, r0
	sub	r1, fp, #92
	mov	r3, #0
	ldr	r0, [fp, #-20]
	bl	send(PLT)
	str	r0, [fp, #-56]
	ldr	r3, [fp, #-56]
	cmp	r3, #0
	blt	.L27
	sub	r3, fp, #92
	mov	r1, r3
	ldr	r3, .L34+28
.LPIC32:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	b	.L23
.L27:
	sub	r3, fp, #92
	mov	r2, r3
	ldr	r1, [fp, #-56]
	ldr	r3, .L34+32
.LPIC33:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	b	.L23
.L24:
	ldr	r3, [fp, #-32]
	ldrb	r3, [r3]	@ zero_extendqisi2
	and	r3, r3, #8
	cmp	r3, #0
	beq	.L29
	ldr	r3, [fp, #-28]
	ldrh	r3, [r3, #2]
	mov	r2, r3
	ldr	r3, [fp, #-112]
	add	r3, r3, r2
	str	r3, [fp, #-44]
	sub	r3, fp, #84
	mov	r2, #16
	mov	r1, r3
	ldr	r0, [fp, #-20]
	bl	connect(PLT)
	mov	r3, r0
	cmp	r3, #0
	bge	.L30
	ldr	r3, .L34+36
.LPIC34:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	b	.L23
.L30:
	ldr	r3, .L34+40
.LPIC35:
	add	r3, pc, r3
	mov	r0, r3
	bl	puts(PLT)
	ldr	r3, [fp, #-44]
	ldrb	r3, [r3, #16]	@ zero_extendqisi2
	mov	r4, r3
	ldr	r3, [fp, #-44]
	ldrb	r3, [r3, #17]	@ zero_extendqisi2
	mov	r5, r3
	ldr	r3, [fp, #-44]
	ldrb	r3, [r3, #18]	@ zero_extendqisi2
	mov	r2, r3
	ldr	r3, [fp, #-44]
	ldrb	r3, [r3, #19]	@ zero_extendqisi2
	mov	r1, r3
	ldr	r3, [fp, #-44]
	ldrb	r3, [r3, #20]	@ zero_extendqisi2
	mov	ip, r3
	ldr	r3, [fp, #-44]
	ldrb	r3, [r3, #21]	@ zero_extendqisi2
	mov	lr, r3
	sub	r0, fp, #100
	ldr	r3, [fp, #-16]
	str	r3, [sp, #20]
	sub	r3, fp, #68
	str	r3, [sp, #16]
	str	lr, [sp, #12]
	str	ip, [sp, #8]
	str	r1, [sp, #4]
	str	r2, [sp]
	mov	r3, r5
	mov	r2, r4
	ldr	r1, .L34+44
.LPIC36:
	add	r1, pc, r1
	bl	sprintf(PLT)
	sub	r3, fp, #100
	mov	r0, r3
	bl	strlen(PLT)
	mov	r2, r0
	sub	r1, fp, #100
	mov	r3, #0
	ldr	r0, [fp, #-20]
	bl	send(PLT)
	str	r0, [fp, #-48]
	ldr	r3, [fp, #-48]
	cmp	r3, #0
	blt	.L31
	sub	r3, fp, #100
	mov	r1, r3
	ldr	r3, .L34+48
.LPIC37:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	b	.L23
.L31:
	sub	r3, fp, #100
	mov	r2, r3
	ldr	r1, [fp, #-48]
	ldr	r3, .L34+52
.LPIC38:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	b	.L23
.L29:
	ldr	r3, [fp, #-32]
	ldrb	r3, [r3]	@ zero_extendqisi2
	and	r3, r3, #4
	cmp	r3, #0
	beq	.L33
	ldr	r3, [fp, #-28]
	ldrh	r3, [r3, #2]
	mov	r2, r3
	ldr	r3, [fp, #-112]
	add	r3, r3, r2
	str	r3, [fp, #-40]
	b	.L23
.L33:
	ldr	r3, [fp, #-32]
	ldrb	r3, [r3]	@ zero_extendqisi2
	mov	r1, r3
	ldr	r3, .L34+56
.LPIC39:
	add	r3, pc, r3
	mov	r0, r3
	bl	printf(PLT)
	ldr	r3, [fp, #-28]
	ldrh	r3, [r3, #2]
	mov	r2, r3
	ldr	r3, [fp, #-112]
	add	r3, r3, r2
	str	r3, [fp, #-36]
.L23:
	ldr	r0, [fp, #-20]
	bl	close(PLT)
	nop
	sub	sp, fp, #12
	@ sp needed
	pop	{r4, r5, fp, pc}
.L35:
	.align	2
.L34:
	.word	.LC10-(.LPIC26+8)
	.word	8888
	.word	.LC11-(.LPIC27+8)
	.word	.LC12-(.LPIC28+8)
	.word	.LC13-(.LPIC29+8)
	.word	.LC14-(.LPIC30+8)
	.word	.LC15-(.LPIC31+8)
	.word	.LC16-(.LPIC32+8)
	.word	.LC17-(.LPIC33+8)
	.word	.LC13-(.LPIC34+8)
	.word	.LC14-(.LPIC35+8)
	.word	.LC15-(.LPIC36+8)
	.word	.LC16-(.LPIC37+8)
	.word	.LC17-(.LPIC38+8)
	.word	.LC18-(.LPIC39+8)
	.size	packetHandler, .-packetHandler
	.ident	"GCC: (Debian 11.2.0-13) 11.2.0"
	.section	.note.GNU-stack,"",%progbits
