// ❶ ──────────────────────────────── 顶部：删掉旧的 feature gate ───────────────────────────

//! Zygisk Dump Dex – stable-Rust 版
//! 兼容 Rust 1.88 及以上；不再需要 `#![feature(naked_functions)]`

// ❷ ──────────────────────────────── 依赖 ────────────────────────────────────────────────

use dobby_rs::Address;
use jni::JNIEnv;
use log::{error, info, trace};
use nix::{fcntl::OFlag, sys::stat::Mode};
use core::arch::asm;                          // ← 替换 naked_asm
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
};
use zygisk_rs::{register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs};

// ❸ ──────────────────────────────── Zygisk 模块实现 ────────────────────────────────────

struct MyModule {
    api: Api,
    env: JNIEnv<'static>,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("dump_dex"),
        );
        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };
        Self { api, env }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let mut inner = || -> anyhow::Result<()> {
            // 取应用包名
            let package_name = self
                .env
                .get_string(unsafe {
                    (args.nice_name as *mut jni_sys::jstring as *mut ()
                        as *const jni::objects::JString<'_>)
                        .as_ref()
                        .unwrap()
                })?
                .to_string_lossy()
                .to_string();
            trace!("pre_app_specialize: package_name: {}", package_name);

            // 读取 list.txt，决定是否启用模块
            let module_dir = self
                .api
                .get_module_dir()
                .ok_or_else(|| anyhow::anyhow!("get_module_dir error"))?;
            let mut list_file = unsafe {
                File::from_raw_fd(nix::fcntl::openat(
                    Some(module_dir.as_raw_fd()),
                    "list.txt",
                    OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?)
            };
            let mut file_content = String::new();
            list_file.read_to_string(&mut file_content)?;
            let enabled = file_content.lines().any(|l| l.trim() == package_name);

            if !enabled {
                // 不在名单 → 卸载自身
                self.api
                    .set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
                return Ok(());
            }

            info!("dump {}", package_name);

            // Hook libdexfile.so::DexFileLoader::OpenCommon
            let open_common = dobby_rs::resolve_symbol(
                "libdexfile.so",
                "_ZN3art13DexFileLoader10OpenCommonENSt3__110shared_ptrINS_16DexFileContainerEEEPKhmRKNS1_12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS1_8optionalIjEEPKNS_10OatDexFileEbbPSC_PNS_22DexFileLoaderErrorCodeE",
            )
            .ok_or_else(|| anyhow::anyhow!("resolve symbol error"))?;

            info!("open_common addr: {:#x}", open_common as usize);
            unsafe {
                OLD_OPEN_COMMON =
                    dobby_rs::hook(open_common, new_open_common_wrapper as Address)? as usize;
            }
            Ok(())
        };

        if let Err(e) = inner() {
            error!("pre_app_specialize error: {:?}", e);
        }
    }

    fn post_app_specialize(&mut self, _args: &AppSpecializeArgs) {}
    fn pre_server_specialize(&mut self, _args: &mut ServerSpecializeArgs) {}
    fn post_server_specialize(&mut self, _args: &ServerSpecializeArgs) {}
}

register_zygisk_module!(MyModule);

// 原函数指针保存处
static mut OLD_OPEN_COMMON: usize = 0;

// ❹ ──────────────────────────────── 裸函数包装 ─────────────────────────────────────────

// 1. `#[naked]` + `unsafe extern "C" fn` 是新规范
// 2. 返回类型必须 `!`，并加 `options(noreturn)`
#[naked]
pub unsafe extern "C" fn new_open_common_wrapper() -> ! {
    asm!(
        // --- 保存寄存器 / 栈帧 ---------------------------------------------------------
        "sub sp, sp, 0x280",
        "stp x29, x30, [sp, #0]",
        "stp x0, x1,  [sp, #0x10]",
        "stp x2, x3,  [sp, #0x20]",
        "stp x4, x5,  [sp, #0x30]",
        "stp x6, x7,  [sp, #0x40]",
        "stp x8, x9,  [sp, #0x50]",

        // --- 参数转换 & 调用自定义逻辑 -----------------------------------------------
        "mov x0, x1",      // base
        "mov x1, x2",      // size
        "bl  {new_open_common}",

        // --- 还原寄存器 / 返回原函数 -------------------------------------------------
        "ldp x29, x30, [sp, #0]",
        "ldp x0, x1,  [sp, #0x10]",
        "ldp x2, x3,  [sp, #0x20]",
        "ldp x4, x5,  [sp, #0x30]",
        "ldp x6, x7,  [sp, #0x40]",
        "ldp x8, x9,  [sp, #0x50]",
        "add sp, sp, 0x280",

        "adrp x16, {old_open_common}",
        "ldr  x16, [x16, #:lo12:{old_open_common}]",
        "br   x16",
        old_open_common  = sym OLD_OPEN_COMMON,
        new_open_common  = sym new_open_common,
        options(noreturn)
    );
}

// ❺ ──────────────────────────────── 新增逻辑：保存 dex 到 /data/data/包名/dexes ────────

extern "C" fn new_open_common(base: usize, size: usize) {
    info!("find dex: base=0x{:x}, size=0x{:x}", base, size);

    let dex_data = unsafe { core::slice::from_raw_parts(base as *const u8, size) };

    // 读包名
    let cmd = match std::fs::read_to_string("/proc/self/cmdline") {
        Ok(c) => c,
        Err(e) => {
            error!("read cmdline error: {:?}", e);
            return;
        }
    };
    let Some(package) = cmd.split('\0').next() else {
        error!("package name parse error: {}", cmd);
        return;
    };

    // 目标目录
    let dir = format!("/data/data/{package}/dexes");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        error!("create dir error: {:?}", e);
        return;
    }

    // 生成文件名（CRC-32）
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_CD_ROM_EDC);
    let mut digest = crc.digest();
    digest.update(dex_data);
    let path = format!("{dir}/{:08x}.dex", digest.finalize());

    // 写文件
    if let Err(e) = std::fs::write(&path, dex_data) {
        error!("write {path} error: {:?}", e);
    } else {
        info!("dumped dex → {path}");
    }
}
