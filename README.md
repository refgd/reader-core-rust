# Legado Rust

本项目改自 Android 阅读项目，核心目标是把书源解析、网络请求和运行时能力迁移到 Rust 实现。

项目不绑定 Android。Android 只是当前 UI 与平台集成之一；核心能力通过 Rust 和 UniFFI 暴露，其他平台只需要替换 UI 和平台边界实现即可接入。

## 方向

- Rust 是主要解析实现。
- 支持 direct-HTTP 书源的搜索、详情、目录、正文流程。
- Android/Kotlin 只负责 UI、WebView、浏览器、媒体播放和 UniFFI 调用。
- 跨平台复用核心逻辑，平台差异放在 UI 与系统能力边界处理。

## 结构

- `crates/legado-runtime`: Rust 运行时与解析核心。
- `crates/legado-cli`: 命令行调试入口。
- `crates/legado-uniffi`: 跨平台绑定接口。

## 构建

```bash
cargo test -p legado-runtime
```


## 许可

本项目使用 `GPL-3.0-only` 许可：

- 允许商业使用。
- 修改、复制、传播或发布时必须保留原作者与版权信息。
- 修改版或衍生版对外发布时必须继续开源，并提供对应源代码。
