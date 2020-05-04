# To snapshot

## Get QEMU

```
sudo apt build-dep qemu
git clone https://github.com/qemu/QEMU
```

## Apply diffs to QEMU to expand snapshot state to include everything we need

```
diff --git a/target/i386/arch_dump.c b/target/i386/arch_dump.c
index 004141fc04..aa71c6f878 100644
--- a/target/i386/arch_dump.c
+++ b/target/i386/arch_dump.c
@@ -264,6 +264,17 @@ struct QEMUCPUState {
      * by checking 'size' field.
      */
     uint64_t kernel_gs_base;
+    uint64_t cr8;
+    uint64_t cstar;
+    uint64_t lstar;
+    uint64_t fmask;
+    uint64_t star;
+    uint64_t sysenter_cs;
+    uint64_t sysenter_esp;
+    uint64_t sysenter_eip;
+    uint64_t efer;
+    uint64_t dr[8];
+    X86LegacyXSaveArea xsave;
 };
 
 typedef struct QEMUCPUState QEMUCPUState;
@@ -322,8 +333,45 @@ static void qemu_get_cpustate(QEMUCPUState *s, CPUX86State *env)
     s->cr[3] = env->cr[3];
     s->cr[4] = env->cr[4];
 
+
 #ifdef TARGET_X86_64
     s->kernel_gs_base = env->kernelgsbase;
+    s->cr8 = cpu_get_apic_tpr(env_archcpu(env)->apic_state);
+    s->cstar = env->cstar;
+    s->lstar = env->lstar;
+    s->fmask = env->fmask;
+    s->star = env->star;
+    s->sysenter_cs = env->sysenter_cs;
+    s->sysenter_esp = env->sysenter_esp;
+    s->sysenter_eip = env->sysenter_eip;
+    s->efer = env->efer;
+    memcpy(s->dr, env->dr, sizeof(s->dr));
+
+    int fpus, fptag, i;
+
+    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
+    fptag = 0;
+    for (i = 0; i < 8; i++) {
+        fptag |= (env->fptags[i] << i);
+    }
+
+    s->xsave.fcw = env->fpuc;
+    s->xsave.fsw = fpus;
+    s->xsave.ftw = fptag ^ 0xff;
+    s->xsave.reserved = 0;
+    s->xsave.fpop = 0;
+    s->xsave.fpip = 0;
+    s->xsave.fpdp = 0;
+    s->xsave.mxcsr = env->mxcsr;
+    s->xsave.mxcsr_mask = 0x0000ffff;
+
+    for(i = 0; i < 8; i++) {
+        s->xsave.fpregs[i] = env->fpregs[i];
+    }
+
+    for(i = 0; i < 16; i++) {
+        memcpy(s->xsave.xmm_regs[i], &env->xmm_regs[i], 16);
+    }
 #endif
 }
```

## Build QEMU

```
mkdir build
cd build
../QEMU/configure --target-list=x86_64-softmmu
make -j32
```

## Run QEMU with a target

```
build/x86_64-softmmu/qemu-system-x86_64 -hda ./DISK.qcow2 -m 4G -cpu core2duo
```

I personally often use, since I have some network devices I can TAP, and I use
KVM for the virt speedup during snapshotting.

```
~/qemu_build/x86_64-softmmu/qemu-system-x86_64 -hda ./DISK.qcow2 -enable-kvm -m 4G -cpu core2duo -smp 1 -vga std -netdev tap,ifname=virbr1-nic,id=mynet -device driver=e1000,netdev=mynet
```

