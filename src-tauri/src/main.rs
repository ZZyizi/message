//! Windows 应用入口点
//!
//! 在非调试模式下编译为 Windows GUI 应用（无控制台窗口）。
//! 直接委托给 `decentralized_im_lib::run()` 启动完整应用。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    decentralized_im_lib::run()
}