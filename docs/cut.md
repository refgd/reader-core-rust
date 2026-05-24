# Rust Replacement Cut List

本文档依据 `docs/js.md` 和新 APP `app/android` 的当前实现，列举所有可以由 Rust analyzer 替代的 direct-HTTP 相关函数，并标明当前是否已经替代。

状态说明：

- 已替代：新 APP 已通过 Rust analyzer / UniFFI / Rust JS host 执行，或 Kotlin 侧只是薄包装。
- 已替代-平台边界：规则仍调用同名 API，但 Rust 只负责统一诊断、参数序列化和 UniFFI platform action；Android 负责 UI、WebView、浏览器、媒体、剪贴板、设备信息等平台动作。
- 已替代-兼容包装：Kotlin 仍保留原签名或 JVM 形态对象，但实现已委托 Rust，便于旧调用点过渡。
- Rust 已实现-待切调用点：Rust 有能力替代，但新 APP 仍可能保留少量非 analyzer UI/业务调用点。
- 不适用：不是规则可调用 API，或只是 Kotlin/Android/Rust 内部桥接结构，不需要继续作为待切函数。

## 总体结论

direct-HTTP 分析主链路已经由 Rust 替代：`search`、`detail`、`toc`、`content`、`explore`、RSS、字典、封面、URL 解析、HTTP TTS/raw fetch、任意 JS/evalRule 都走 `RustAnalyzerBridge` 到 UniFFI。新 APP 不应恢复 Kotlin `AnalyzeUrl`、`AnalyzeRule`、Rhino 或 OkHttp helper 作为 direct-HTTP fallback。

Android/Kotlin 仍保留的合理边界是 UI、WebView、浏览器、媒体播放、Intent、剪贴板、设备/APP 配置读取，以及把 Rust 结果转换成现有 Android 数据对象。

## Analyzer / UniFFI 入口

| 函数/入口 | 位置 | 是否已替代 | 说明 |
|---|---|---:|---|
| `RustAnalyzerBridge.canHandle` | 新 APP | 已替代 | 统一判断 Rust UniFFI 是否可用；不再按书源回退旧 analyzer |
| `RustAnalyzerBridge.search` | 新 APP | 已替代 | 替代 direct-HTTP 搜索 |
| `RustAnalyzerBridge.explore` | 新 APP | 已替代 | 替代发现分类下的书籍列表 |
| `RustAnalyzerBridge.exploreKinds` | 新 APP | 已替代 | 替代发现分类解析 |
| `RustAnalyzerBridge.detail` | 新 APP | 已替代 | 替代书籍详情解析 |
| `RustAnalyzerBridge.toc` | 新 APP | 已替代 | 替代目录解析 |
| `RustAnalyzerBridge.preUpdateToc` | 新 APP | 已替代 | 替代 `preUpdateJs` 目录更新动作 |
| `RustAnalyzerBridge.content` | 新 APP | 已替代 | 替代章节正文解析 |
| `RustAnalyzerBridge.rssSortUrls` | 新 APP | 已替代 | 替代 RSS 分类 URL 解析 |
| `RustAnalyzerBridge.rssArticles` | 新 APP | 已替代 | 替代 RSS 文章列表解析 |
| `RustAnalyzerBridge.rssContent` | 新 APP | 已替代 | 替代 RSS 正文解析 |
| `RustAnalyzerBridge.dictSearch` | 新 APP | 已替代 | 替代字典源 showRule 解析 |
| `RustAnalyzerBridge.coverSearch` | 新 APP | 已替代 | 替代封面搜索规则解析 |
| `RustAnalyzerBridge.resolveUrl` | 新 APP | 已替代 | 替代 `AnalyzeUrl` URL 规则解析 |
| `RustAnalyzerBridge.directLinkUpload` | 新 APP | 已替代 | 替代 direct-link multipart 上传 |
| `RustAnalyzerBridge.resolveMediaRequest` | 新 APP | 已替代-平台边界 | Rust 解析 URL/header，Android 创建 ExoPlayer 请求 |
| `RustAnalyzerBridge.resolveMediaItem` | 新 APP | 已替代-平台边界 | Rust 解析媒体 URL，Android 创建媒体对象 |
| `RustAnalyzerBridge.fetchText` | 新 APP | 已替代 | 替代文本请求 helper |
| `RustAnalyzerBridge.fetchRaw` | 新 APP | 已替代 | 替代二进制请求 helper |
| `RustAnalyzerBridge.fetchRawUrl` | 新 APP | 已替代 | 无源 URL raw fetch 入口 |
| `RustAnalyzerBridge.fetchRawResponse` | 新 APP | 已替代 | 返回 raw body/header/status |
| `RustAnalyzerBridge.fetchTtsAudio` | 新 APP | 已替代 | 替代 HTTP TTS 请求解析和下载 |
| `RustAnalyzerBridge.evalJs` | 新 APP | 已替代 | 替代 analyzer JS 执行 |
| `RustAnalyzerBridge.evalJsAny` | 新 APP | 已替代 | 替代 JS 执行并解码 Rust marker |
| `RustAnalyzerBridge.evalRule` | 新 APP | 已替代 | 替代 `AnalyzeRule` 任意规则执行 |
| `RustAnalyzerBridge.evalJsRaw` | 新 APP | 已替代 | 低层 Rust eval JSON 入口 |
| `RustAnalyzerBridge.analyzeRaw` | 新 APP | 已替代 | 低层 UniFFI analyze JSON 入口 |
| `RustAnalyzerBridge.decodeEvalResult` | 新 APP | 已替代-兼容包装 | 解码 Rust JS 返回对象给 Kotlin |
| `RustAnalyzerBridge.effectiveDomain` | 新 APP | 已替代 | Rust public suffix/domain helper |
| `RustAnalyzerBridge.applyCookieToWebView` | 新 APP | 已替代-平台边界 | Rust cookie store 同步到 Android WebView |
| `RustAnalyzerBridge.configurePersistentStore` | 新 APP | 已替代 | Rust analyzer 持久化目录初始化 |

## 全局 JS / 规则调度函数

| 函数/语法 | 是否已替代 | 说明 |
|---|---:|---|
| `request(url)` | 已替代 | 全局请求函数由 Rust host 实现 |
| `request(url, method, body, headers, timeout)` | 已替代 | 支持方法、body、headers、timeout |
| `<js>...</js>` | 已替代 | 规则链 JS 由 Rust/rquickjs 执行 |
| `@js:...` | 已替代 | URL 段和字段规则 JS 均由 Rust 执行 |
| `{{js}}` | 已替代 | 模板 JS 替换由 Rust 执行 |
| `@get:key` | 已替代 | Rust store 读取 |
| `@put:{...}` | 已替代 | Rust store 写入 |
| `@CSS:` / `@@` | 已替代 | Rust 规则模式分发 |
| `@XPath:` / `/...` | 已替代 | Rust XPath 兼容子集，复杂不可表达形态 fail-fast |
| `@Json:` / `$.` / `$[` | 已替代 | Rust JSONPath |
| `##regex##replacement` | 已替代 | Rust 正则替换 |
| `##regex##replacement###` | 已替代 | Rust 首匹配替换 |
| `$1` / `$2` 正则组 | 已替代 | Rust replacement group expansion |
| `<webJs>...</webJs>` | 已替代-平台边界 | Rust 诊断/转发 WebView host |

## `java` 网络 API

| JS 函数 | Kotlin wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `java.ajax(url)` | `JsExtensions.ajax(url)` | 已替代 | Rust 请求返回 body |
| `java.ajax(url, callTimeout)` | `JsExtensions.ajax(url, callTimeout)` | 已替代 | 支持超时 |
| `java.ajaxAll(urlList)` | `JsExtensions.ajaxAll(urlList)` | 已替代 | Rust 并发请求 |
| `java.ajaxAll(urlList, skipRateLimit)` | `JsExtensions.ajaxAll(urlList, skipRateLimit)` | 已替代 | 支持源并发率和跳过限速 |
| `java.ajaxTestAll(urlList, timeout)` | `JsExtensions.ajaxTestAll(urlList, timeout)` | 已替代 | Rust 测速并返回兼容错误码 |
| `java.ajaxTestAll(urlList, timeout, skipRateLimit)` | `JsExtensions.ajaxTestAll(...)` | 已替代 | 同上 |
| `java.connect(url)` | `JsExtensions.connect(url)` | 已替代 | Rust `StrResponse` |
| `java.connect(url, header)` | `JsExtensions.connect(url, header)` | 已替代 | 支持附加 header |
| `java.connect(url, header, callTimeout)` | `JsExtensions.connect(...)` | 已替代 | 支持超时 |
| `java.get(url, headers)` | `JsExtensions.get(url, headers)` | 已替代 | Rust JSoup-style GET response |
| `java.get(url, headers, timeout)` | `JsExtensions.get(...)` | 已替代 | 支持超时 |
| `java.head(url, headers)` | `JsExtensions.head(url, headers)` | 已替代 | Rust HEAD |
| `java.head(url, headers, timeout)` | `JsExtensions.head(...)` | 已替代 | 支持超时 |
| `java.post(url, body, headers)` | `JsExtensions.post(url, body, headers)` | 已替代 | Rust POST |
| `java.post(url, body, headers, timeout)` | `JsExtensions.post(...)` | 已替代 | 支持超时 |

## `StrResponse` / JSoup response 兼容方法

| 函数/方法 | 是否已替代 | 说明 |
|---|---:|---|
| `StrResponse.body()` | 已替代 | Rust response wrapper |
| `StrResponse.code()` / `statusCode()` | 已替代 | Rust status code |
| `StrResponse.message()` / `statusMessage()` | 已替代 | Rust status message |
| `StrResponse.url()` | 已替代 | 最终 URL |
| `StrResponse.headers()` | 已替代 | header map |
| `StrResponse.headers(name)` | 已替代 | 指定 header 多值 |
| `StrResponse.header(name)` | 已替代 | 指定 header 首值 |
| `StrResponse.headersList()` | 已替代 | 保留重复 header |
| `StrResponse.contentType()` | 已替代 | Content-Type |
| `StrResponse.isSuccessful()` | 已替代 | 2xx 判断 |
| `StrResponse.callTime()` | 已替代 | 测速耗时/负错误码 |
| `Connection.Response.statusCode/statusMessage` | 已替代-兼容包装 | `RustConnectionResponse` |
| `Connection.Response.charset/contentType` | 已替代-兼容包装 | `RustConnectionResponse` |
| `Connection.Response.parse/body/bodyAsBytes/bodyStream` | 已替代-兼容包装 | `RustConnectionResponse` |
| `Connection.Response.url/method` | 已替代-兼容包装 | `RustConnectionResponse` |
| `Connection.Response.header/headers/headers/multiHeaders` | 已替代-兼容包装 | `RustConnectionResponse` |
| `Connection.Response.cookie/cookies/hasCookie/removeCookie` | 已替代-兼容包装 | `RustConnectionResponse` |

## `java` WebView / 浏览器 / 媒体 / UI API

| JS 函数 | Kotlin wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `java.webView(html,url,js)` | `JsExtensions.webView(...)` | 已替代-平台边界 | Rust platform action 到 Android WebView |
| `java.webView(html,url,js,cacheFirst)` | `JsExtensions.webView(...)` | 已替代-平台边界 | 同上 |
| `java.webViewGetSource(...)` | `JsExtensions.webViewGetSource(...)` | 已替代-平台边界 | WebView 资源捕获 |
| `java.webViewGetOverrideUrl(...)` | `JsExtensions.webViewGetOverrideUrl(...)` | 已替代-平台边界 | WebView 跳转捕获 |
| `java.openVideoPlayer(url,title)` | `JsExtensions.openVideoPlayer(url,title)` | 已替代-平台边界 | Android 播放器 |
| `java.openVideoPlayer(url,title,isFloat)` | `JsExtensions.openVideoPlayer(...)` | 已替代-平台边界 | Android 播放器 |
| `java.startBrowser(url,title)` | `JsExtensions.startBrowser(...)` | 已替代-平台边界 | Android 浏览器/验证 |
| `java.startBrowser(url,title,html)` | `JsExtensions.startBrowser(...)` | 已替代-平台边界 | Android 浏览器/验证 |
| `java.startBrowserAwait(url,title)` | `JsExtensions.startBrowserAwait(...)` | 已替代-平台边界 | 返回 Rust response wrapper |
| `java.startBrowserAwait(url,title,refetchAfterSuccess)` | `JsExtensions.startBrowserAwait(...)` | 已替代-平台边界 | 同上 |
| `java.startBrowserAwait(url,title,refetchAfterSuccess,html)` | `JsExtensions.startBrowserAwait(...)` | 已替代-平台边界 | 同上 |
| `java.showBrowser(...)` | `SourceLoginJsExtensions.showBrowser(...)` | 已替代-平台边界 | 登录 UI 浏览器 |
| `java.startBrowserDp(...)` | Rust host / platform | 已替代-平台边界 | DP/特定浏览器流程 |
| `java.showReadingBrowser(...)` | Rust host / platform | 已替代-平台边界 | 阅读浏览器 |
| `java.getVerificationCode(imageUrl)` | `JsExtensions.getVerificationCode(...)` | 已替代-平台边界 | Android 验证码 UI |
| `java.copyText(text)` | `SourceLoginJsExtensions.copyText(...)` | 已替代-平台边界 | Android 剪贴板 |
| `java.openUrl(url)` | `JsExtensions.openUrl(url)` | 已替代-平台边界 | Android Intent |
| `java.openUrl(url,mimeType)` | `JsExtensions.openUrl(...)` | 已替代-平台边界 | Android Intent |
| `java.getWebViewUA()` | `JsExtensions.getWebViewUA()` | 已替代-平台边界 | Android WebView UA |
| `java.androidId()` | `JsExtensions.androidId()` | 已替代-平台边界 | Android 设备 ID |
| `java.getAppVersionName()` | `JsExtensions.getAppVersionName()` | 已替代-平台边界 | Android app info |
| `java.getAppVersionCode()` | `JsExtensions.getAppVersionCode()` | 已替代-平台边界 | Android app info |
| `java.getAppVariant()` | `JsExtensions.getAppVariant()` | 已替代-平台边界 | Android build variant |
| `java.getReadBookConfig()` | `JsExtensions.getReadBookConfig()` | 已替代-平台边界 | Android 阅读配置 JSON |
| `java.getReadBookConfigMap()` | `JsExtensions.getReadBookConfigMap()` | 已替代-平台边界 | Android 阅读配置 map |
| `java.getThemeMode()` | `JsExtensions.getThemeMode()` | 已替代-平台边界 | Android 主题模式 |
| `java.getThemeConfig()` | `JsExtensions.getThemeConfig()` | 已替代-平台边界 | Android 主题配置 JSON |
| `java.getThemeConfigMap()` | `JsExtensions.getThemeConfigMap()` | 已替代-平台边界 | Android 主题配置 map |
| `java.showPhoto(src)` | `RssJsExtensions.showPhoto(...)` | 已替代-平台边界 | Rust platform action 已接普通 RSS 和登录上下文 |
| `java.searchBook(key,scope)` | `RssJsExtensions.searchBook(...)` | 已替代-平台边界 | Rust platform action 已接普通 RSS 和登录上下文 |
| `java.addBook(bookUrl)` | `RssJsExtensions.addBook(...)` | 已替代-平台边界 | Rust platform action 已接普通 RSS 和登录上下文 |
| `java.open(name,url,title,origin)` | `RssJsExtensions.open(...)` / `SourceLoginJsExtensions.open(...)` | 已替代-平台边界 | Rust platform action 已接普通 RSS 和登录上下文 |
| `java.reLoginView(deltaUp)` | `SourceLoginJsExtensions.reLoginView(...)` | 已替代-平台边界 | 登录 UI 刷新 |
| `java.upLoginData(data)` | `SourceLoginJsExtensions.upLoginData(...)` | 已替代-平台边界 | 登录 UI 数据更新 |
| `java.refreshBookInfo()` | `SourceLoginJsExtensions.refreshBookInfo()` | 已替代-平台边界 | Android 刷新 |
| `java.refreshBookToc()` | `SourceLoginJsExtensions.refreshBookToc()` | 已替代-平台边界 | Android 刷新 |
| `java.refreshContent()` | `SourceLoginJsExtensions.refreshContent()` | 已替代-平台边界 | Android 刷新 |
| `java.clearTtsCache()` | `SourceLoginJsExtensions.clearTtsCache()` | 已替代-平台边界 | Android TTS cache |
| `java.refreshExplore()` | `SourceLoginJsExtensions.refreshExplore()` | 已替代-平台边界 | Android 发现页刷新 |

## `java` 文件 / 缓存 / 压缩包 / 字体 API

| JS 函数 | Kotlin wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `java.importScript(path)` | `JsExtensions.importScript(path)` | 已替代 | Rust 请求/virtual file |
| `java.cacheFile(url)` | `JsExtensions.cacheFile(url)` | 已替代 | Rust 下载并缓存文本 |
| `java.cacheFile(url, saveTime)` | `JsExtensions.cacheFile(url, saveTime)` | 已替代 | 接收兼容参数 |
| `java.downloadFile(url)` | `JsExtensions.downloadFile(url)` | 已替代 | Rust virtual file |
| `java.downloadFile(content,url)` / `java.__downloadHexFile` | `JsExtensions.downloadFile(content,url)` | 已替代 | hex 写文件兼容 |
| `java.getFile(path)` | `JsExtensions.getFile(path)` | 已替代-兼容包装 | 返回 `RustFile` 而非 Android `File` |
| `java.readFile(path)` | `JsExtensions.readFile(path)` | 已替代 | Rust virtual file bytes |
| `java.readTxtFile(path)` | `JsExtensions.readTxtFile(path)` | 已替代 | Rust virtual file text |
| `java.readTxtFile(path, charset)` | `JsExtensions.readTxtFile(path, charset)` | 已替代 | 支持 charset |
| `java.writeTxtFile(path,text)` | Rust host | 已替代 | Rust virtual file |
| `java.deleteFile(path)` | `JsExtensions.deleteFile(path)` | 已替代 | Rust virtual file/cache |
| `java.fileExist(path)` | Rust host / `RustFile.exists` | 已替代 | Rust virtual file |
| `java.unzipFile(path)` | `JsExtensions.unzipFile(path)` | 已替代 | Rust 解压 |
| `java.un7zFile(path)` | `JsExtensions.un7zFile(path)` | 已替代 | Rust 解压 |
| `java.unrarFile(path)` | `JsExtensions.unrarFile(path)` | 已替代 | Rust 解压 |
| `java.unArchiveFile(path)` | `JsExtensions.unArchiveFile(path)` | 已替代 | Rust 按扩展名解压 |
| `java.getTxtInFolder(path)` | `JsExtensions.getTxtInFolder(path)` | 已替代 | Rust 读取目录文本 |
| `java.getZipStringContent(url,path)` | `JsExtensions.getZipStringContent(...)` | 已替代 | Rust archive reader |
| `java.getZipStringContent(url,path,charset)` | `JsExtensions.getZipStringContent(...)` | 已替代 | 支持 charset |
| `java.getZipByteArrayContent(url,path)` | `JsExtensions.getZipByteArrayContent(...)` | 已替代 | Rust archive reader |
| `java.getRarStringContent(url,path)` | `JsExtensions.getRarStringContent(...)` | 已替代 | Rust archive reader |
| `java.getRarStringContent(url,path,charset)` | `JsExtensions.getRarStringContent(...)` | 已替代 | 支持 charset |
| `java.getRarByteArrayContent(url,path)` | `JsExtensions.getRarByteArrayContent(...)` | 已替代 | Rust archive reader |
| `java.get7zStringContent(url,path)` | `JsExtensions.get7zStringContent(...)` | 已替代 | Rust archive reader |
| `java.get7zStringContent(url,path,charset)` | `JsExtensions.get7zStringContent(...)` | 已替代 | 支持 charset |
| `java.get7zByteArrayContent(url,path)` | `JsExtensions.get7zByteArrayContent(...)` | 已替代 | Rust archive reader |
| `java.queryTTF(data)` | `JsExtensions.queryTTF(data)` | 已替代 | Rust TTF parser |
| `java.queryTTF(data,useCache)` | `JsExtensions.queryTTF(data,useCache)` | 已替代 | Rust TTF parser |
| `java.queryBase64TTF(data)` | `JsExtensions.queryBase64TTF(data)` | 已替代 | alias |
| `java.replaceFont(text,errorTTF,correctTTF)` | `JsExtensions.replaceFont(...)` | 已替代 | Rust 字体反混淆 |
| `java.replaceFont(text,errorTTF,correctTTF,filter)` | `JsExtensions.replaceFont(...)` | 已替代 | 支持 filter |
| `QueryTTF.getGlyfIdByUnicode` | Rust JS object | 已替代 | Rust TTF object |
| `QueryTTF.getGlyfByUnicode` | Rust JS object | 已替代 | Rust TTF object |
| `QueryTTF.getUnicodeByGlyf` | Rust JS object | 已替代 | Rust TTF object |
| `QueryTTF.isBlankUnicode` | Rust JS object | 已替代 | Rust TTF object |
| `RustFile.exists/isFile/isDirectory/length/readBytes/readText/delete` | `RustFile` | 已替代-兼容包装 | Kotlin 文件形态 wrapper，底层调用 Rust |

## `java` 编码 / 文本 / 时间 / 日志 API

| JS 函数 | Kotlin wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `java.strToBytes(str)` | `JsExtensions.strToBytes(str)` | 已替代 | Rust byte wrapper |
| `java.strToBytes(str, charset)` | `JsExtensions.strToBytes(str, charset)` | 已替代 | 支持 charset |
| `java.bytesToStr(bytes)` | `JsExtensions.bytesToStr(bytes)` | 已替代 | Rust byte wrapper |
| `java.bytesToStr(bytes, charset)` | `JsExtensions.bytesToStr(bytes, charset)` | 已替代 | 支持 charset |
| `java.base64Decode(str)` | `JsExtensions.base64Decode(str)` | 已替代 | Rust base64 |
| `java.base64Decode(str, charset)` | `JsExtensions.base64Decode(str, charset)` | 已替代 | 支持 charset |
| `java.base64Decode(str, flags)` | `JsExtensions.base64Decode(str, flags)` | 已替代 | Android flags 兼容 |
| `java.base64DecodeToByteArray(str)` | `JsExtensions.base64DecodeToByteArray(str)` | 已替代 | Rust byte wrapper |
| `java.base64DecodeToByteArray(str, flags)` | `JsExtensions.base64DecodeToByteArray(str, flags)` | 已替代 | Android flags 兼容 |
| `java.base64Encode(str)` | `JsExtensions.base64Encode(str)` | 已替代 | Rust base64 |
| `java.base64Encode(str, flags)` | `JsExtensions.base64Encode(str, flags)` | 已替代 | Android flags 兼容 |
| `java.hexDecodeToByteArray(hex)` | `JsExtensions.hexDecodeToByteArray(hex)` | 已替代 | Rust hex |
| `java.hexDecodeToString(hex)` | `JsExtensions.hexDecodeToString(hex)` | 已替代 | Rust hex |
| `java.hexEncodeToString(str)` | `JsExtensions.hexEncodeToString(str)` | 已替代 | Rust hex |
| `java.timeFormat(time)` | `JsExtensions.timeFormat(time)` | 已替代 | Rust 时间格式 |
| `java.timeFormatUTC(time,format,sh)` | `JsExtensions.timeFormatUTC(...)` | 已替代 | Rust 时间格式 |
| `java.encodeURI(str)` | `JsExtensions.encodeURI(str)` | 已替代 | Rust URL encode |
| `java.encodeURI(str, enc)` | `JsExtensions.encodeURI(str, enc)` | 已替代 | Rust URL encode |
| `java.htmlFormat(str)` | `JsExtensions.htmlFormat(str)` | 已替代 | Rust HTML formatter |
| `java.t2s(text)` | `JsExtensions.t2s(text)` | 已替代 | Rust 繁转简 |
| `java.s2t(text)` | `JsExtensions.s2t(text)` | 已替代 | Rust 简转繁 |
| `java.toNumChapter(s)` | `JsExtensions.toNumChapter(s)` | 已替代 | Rust 章节数字归一 |
| `java.toURL(url)` | `JsExtensions.toURL(url)` | 已替代 | Rust URL object |
| `java.toURL(url, baseUrl)` | `JsExtensions.toURL(url, baseUrl)` | 已替代 | Rust URL object |
| `java.toast(msg)` | `JsExtensions.toast(msg)` | 已替代-平台边界 | Rust session + platform toast |
| `java.longToast(msg)` | `JsExtensions.longToast(msg)` | 已替代-平台边界 | Rust session + platform toast |
| `java.log(msg)` | `JsExtensions.log(msg)` | 已替代-平台边界 | Rust session + platform log |
| `java.logType(any)` | `JsExtensions.logType(any)` | 已替代-平台边界 | Rust log type |
| `java.randomUUID()` | `JsExtensions.randomUUID()` | 已替代 | Rust UUID |
| `java.getSource()` | Rust host | 已替代 | 返回 `source` object |
| `java.getTag()` | Rust host / Kotlin wrapper | 已替代 | 返回 source tag/name |
| `java.getCookie(tag)` | `JsExtensions.getCookie(tag)` | 已替代 | Rust cookie object |
| `java.getCookie(tag,key)` | `JsExtensions.getCookie(tag,key)` | 已替代 | Rust cookie key |

## `java` 加密 / 摘要 API

| JS 函数/对象方法 | Kotlin wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `java.md5Encode(str)` | `JsEncodeUtils.md5Encode` | 已替代 | Rust MD5 |
| `java.md5Encode16(str)` | `JsEncodeUtils.md5Encode16` | 已替代 | Rust MD5 16 |
| `java.digestHex(data,algorithm)` | `JsEncodeUtils.digestHex` | 已替代 | Rust digest |
| `java.digestBase64Str(data,algorithm)` | `JsEncodeUtils.digestBase64Str` | 已替代 | Rust digest |
| `java.HMacHex(data,algorithm,key)` | `JsEncodeUtils.HMacHex` | 已替代 | Rust HMAC |
| `java.HMacBase64(data,algorithm,key)` | `JsEncodeUtils.HMacBase64` | 已替代 | Rust HMAC |
| `java.createSymmetricCrypto(transformation,key)` | `JsEncodeUtils.createSymmetricCrypto` | 已替代 | Rust symmetric crypto |
| `java.createSymmetricCrypto(transformation,key,iv)` | `JsEncodeUtils.createSymmetricCrypto` | 已替代 | Rust symmetric crypto |
| `crypto.setIv(iv)` | `RustSymmetricCrypto.setIv` | 已替代-兼容包装 | 底层 Rust |
| `crypto.encrypt(data)` | `RustSymmetricCrypto.encrypt` | 已替代-兼容包装 | 底层 Rust |
| `crypto.encryptBase64(data)` | `RustSymmetricCrypto.encryptBase64` | 已替代-兼容包装 | 底层 Rust |
| `crypto.encryptHex(data)` | `RustSymmetricCrypto.encryptHex` | 已替代-兼容包装 | 底层 Rust |
| `crypto.decrypt(data)` | `RustSymmetricCrypto.decrypt` | 已替代-兼容包装 | 底层 Rust |
| `crypto.decryptStr(data)` | `RustSymmetricCrypto.decryptStr` | 已替代-兼容包装 | 底层 Rust |
| `java.createAsymmetricCrypto(transformation)` | `JsEncodeUtils.createAsymmetricCrypto` | 已替代 | Rust RSA 常见路径 |
| `asym.setPublicKey(key)` | `RustAsymmetricCrypto.setPublicKey` | 已替代-兼容包装 | 底层 Rust |
| `asym.setPrivateKey(key)` | `RustAsymmetricCrypto.setPrivateKey` | 已替代-兼容包装 | 底层 Rust |
| `asym.encryptBase64(data,usePublicKey)` | `RustAsymmetricCrypto.encryptBase64` | 已替代-兼容包装 | 底层 Rust |
| `asym.encryptHex(data,usePublicKey)` | `RustAsymmetricCrypto.encryptHex` | 已替代-兼容包装 | 底层 Rust |
| `asym.encrypt(data,usePublicKey)` | `RustAsymmetricCrypto.encrypt` | 已替代-兼容包装 | 底层 Rust |
| `asym.decryptStr(data,usePublicKey)` | `RustAsymmetricCrypto.decryptStr` | 已替代-兼容包装 | 底层 Rust |
| `asym.decrypt(data,usePublicKey)` | `RustAsymmetricCrypto.decrypt` | 已替代-兼容包装 | 底层 Rust |
| `java.createSign(algorithm)` | `JsEncodeUtils.createSign` | 已替代 | Rust RSA sign |
| `sign.setPublicKey(key)` | `RustSign.setPublicKey` | 已替代-兼容包装 | 底层 Rust |
| `sign.setPrivateKey(key)` | `RustSign.setPrivateKey` | 已替代-兼容包装 | 底层 Rust |
| `sign.signHex(data)` | `RustSign.signHex` | 已替代-兼容包装 | 底层 Rust |
| `sign.signBase64(data)` | Rust JS object | 已替代 | Rust sign |
| `sign.sign(data)` | `RustSign.sign` | 已替代-兼容包装 | Base64 alias |
| `java.aesDecodeToByteArray` | `JsEncodeUtils.aesDecodeToByteArray` | 已替代 | Rust AES wrapper |
| `java.aesDecodeToString` | `JsEncodeUtils.aesDecodeToString` | 已替代 | Rust AES wrapper |
| `java.aesDecodeArgsBase64Str` | `JsEncodeUtils.aesDecodeArgsBase64Str` | 已替代 | Rust AES wrapper |
| `java.aesBase64DecodeToByteArray` | `JsEncodeUtils.aesBase64DecodeToByteArray` | 已替代 | Rust AES wrapper |
| `java.aesBase64DecodeToString` | `JsEncodeUtils.aesBase64DecodeToString` | 已替代 | Rust AES wrapper |
| `java.aesEncodeToByteArray` | `JsEncodeUtils.aesEncodeToByteArray` | 已替代 | Rust AES wrapper |
| `java.aesEncodeToString` | `JsEncodeUtils.aesEncodeToString` | 已替代 | 保留原 APP 旧方法形态 |
| `java.aesEncodeToBase64ByteArray` | `JsEncodeUtils.aesEncodeToBase64ByteArray` | 已替代 | Rust AES wrapper |
| `java.aesEncodeToBase64String` | `JsEncodeUtils.aesEncodeToBase64String` | 已替代 | Rust AES wrapper |
| `java.aesEncodeArgsBase64Str` | `JsEncodeUtils.aesEncodeArgsBase64Str` | 已替代 | Rust AES wrapper |
| `java.desDecodeToString` | `JsEncodeUtils.desDecodeToString` | 已替代 | Rust DES wrapper |
| `java.desBase64DecodeToString` | `JsEncodeUtils.desBase64DecodeToString` | 已替代 | Rust DES wrapper |
| `java.desEncodeToString` | `JsEncodeUtils.desEncodeToString` | 已替代 | Rust DES wrapper |
| `java.desEncodeToBase64String` | `JsEncodeUtils.desEncodeToBase64String` | 已替代 | Rust DES wrapper |
| `java.tripleDESDecodeStr` | `JsEncodeUtils.tripleDESDecodeStr` | 已替代 | Rust 3DES wrapper |
| `java.tripleDESDecodeArgsBase64Str` | `JsEncodeUtils.tripleDESDecodeArgsBase64Str` | 已替代 | Rust 3DES wrapper |
| `java.tripleDESEncodeBase64Str` | `JsEncodeUtils.tripleDESEncodeBase64Str` | 已替代 | Rust 3DES wrapper |
| `java.tripleDESEncodeArgsBase64Str` | `JsEncodeUtils.tripleDESEncodeArgsBase64Str` | 已替代 | Rust 3DES wrapper |

## `source` API

| JS 函数/属性 | Kotlin wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `source.bookSourceUrl` / `source.sourceUrl` | source entity field | 已替代 | Rust source object |
| `source.bookSourceName` / `source.sourceName` | source entity field | 已替代 | Rust source object |
| `source.jsLib` | source entity field | 已替代 | Rust 加载并保持 shared scope |
| `source.loginUrl` | source entity field | 已替代 | Rust 兼容 `@js:`/`<js>` |
| `source.header` | source entity field | 已替代 | Rust header parser |
| `source.variableComment` | source entity field | 已替代 | Rust extra field |
| `source.getKey()` | source object | 已替代 | Rust source key |
| `source.getHeaderMap()` | source object | 已替代 | Rust header map |
| `source.getHeaderMap(hasLoginHeader)` | source object | 已替代 | 合并登录 header |
| `source.getVariable()` | source object | 已替代 | Rust source variable |
| `source.getVariable(key)` | source object | 已替代 | Rust source variable |
| `source.setVariable(json)` | source object | 已替代 | Rust source variable |
| `source.setVariable(key,value)` | source object | 已替代 | Rust source variable |
| `source.putVariable(key,value)` | source object | 已替代 | Rust source variable |
| `source.put(key,value)` | `RssJsExtensions.put` / BaseSource helpers | 已替代 | Rust persistent source KV |
| `source.get(key)` | `RssJsExtensions.get` / BaseSource helpers | 已替代 | Rust persistent source KV |
| `source.getLoginInfo()` | source object | 已替代 | Rust login info |
| `source.getLoginInfoMap()` | source object | 已替代 | Rust map-like object |
| `source.putLoginInfo(json)` | source object | 已替代 | Rust login info |
| `source.putLoginInfo(key,value)` | source object | 已替代 | Rust login info |
| `source.removeLoginInfo()` | source object | 已替代 | Rust login info |
| `source.getLoginHeader()` | source object | 已替代 | Rust login header |
| `source.getLoginHeaderMap()` | source object | 已替代 | Rust login header map |
| `source.putLoginHeader(header)` | source object | 已替代 | Rust login header + cookie sync |
| `source.removeLoginHeader()` | source object | 已替代 | Rust login header |
| `source.loginUi` | source object | 已替代-平台边界 | 文本/函数兼容，实际 UI 属 Android |
| `source.refreshExplore()` | source object / login UI | 已替代-平台边界 | Android 刷新动作 |
| `source.refreshJSLib()` | source object | 已替代 | Rust 清 jsLib/import 缓存 |
| `source.putConcurrent(value)` | source object | 已替代 | Rust 更新源级并发率 |
| `source.login()` | source object | 已替代-平台边界 | Rust 执行 login JS；内部 UI/WebView 动作走平台边界 |

## `cache` / `cookie` / `book` / `chapter`

| JS 函数/属性 | 是否已替代 | 说明 |
|---|---:|---|
| `cache.get(key)` | 已替代 | Rust persistent cache |
| `cache.put(key,value)` | 已替代 | Rust persistent cache |
| `cache.delete(key)` | 已替代 | Rust cache delete |
| `cache.putFile(key,value,saveTime)` | 已替代 | Rust file-cache |
| `cache.getFile(key)` | 已替代 | Rust file-cache |
| `cache.putMemory(key,value)` | 已替代 | Rust session memory |
| `cache.getFromMemory(key)` | 已替代 | Rust session memory |
| `cache.deleteMemory(key)` | 已替代 | Rust session memory |
| `cache.putVariable(key,value)` | 已替代 | alias |
| `cache.setVariable(key,value)` | 已替代 | alias |
| `cache.getVariable(key)` | 已替代 | alias |
| `cookie.getCookie(host)` | 已替代 | Rust cookie store |
| `cookie.getKey(host,key)` | 已替代 | Rust cookie store |
| `cookie.setCookie(host,value)` | 已替代 | Rust cookie store |
| `cookie.replaceCookie(host,value)` | 已替代 | alias |
| `cookie.setWebCookie(host,value)` | 已替代-平台边界 | Android WebView cookie |
| `cookie.removeCookie(host)` | 已替代 | Rust cookie store |
| `book.get(key)` | 已替代 | Rust book variable |
| `book.put(key,value)` | 已替代 | Rust book variable |
| `book.delete(key)` | 已替代 | Rust book variable |
| `book.getVariable(key)` | 已替代 | alias |
| `book.putVariable(key,value)` | 已替代 | alias |
| `book.setVariable(key,value)` | 已替代 | alias |
| `book.setUseReplaceRule(bool)` | 已替代 | Rust book variable |
| `book.getUseReplaceRule()` | 已替代 | Rust book variable |
| `book.durChapterTitle` | 已替代 | Android bridge binding + Rust session 回写 |
| `book.durChapterIndex` | 已替代 | Android bridge binding + Rust session 回写 |
| `chapter.get(key)` | 已替代 | Rust chapter variable |
| `chapter.put(key,value)` | 已替代 | Rust chapter variable |
| `chapter.delete(key)` | 已替代 | Rust chapter variable |
| `chapter.getVariable(key)` | 已替代 | alias |
| `chapter.putVariable(key,value)` | 已替代 | alias |
| `chapter.setVariable(key,value)` | 已替代 | alias |
| `chapter.putLyric(value)` | 已替代 | Rust variable 回写 Android chapter |
| `chapter.putImgUrl(value)` | 已替代 | Rust variable 回写 Android chapter |
| `chapter.index` | 已替代 | Android bridge binding + Rust session 回写 |

## AnalyzeRule 兼容方法

| 原方法 | 新 APP wrapper | 是否已替代 | 说明 |
|---|---|---:|---|
| `setRuleName(name)` | 无需保留 | 不适用 | Rust 使用 rule_path/source diagnostics |
| `setContent(content,baseUrl)` | `RssRustRuleBridge.setContent` | 已替代 | Rust 内容类型检测 |
| `setBaseUrl(baseUrl)` | `RssRustRuleBridge.setBaseUrl` | 已替代 | Rust input/base URL |
| `setRedirectUrl(url)` | `RssRustRuleBridge.setRedirectUrl` | 已替代 | Rust redirect/base URL |
| `getStringList(rule,content,isUrl)` | `RssRustRuleBridge.getStringList` | 已替代 | Rust rule engine |
| `getString(rule,content,isUrl)` | `RssRustRuleBridge.getString` | 已替代 | Rust rule engine |
| `getString(rule,unescape)` | `RssRustRuleBridge.getString` | 已替代 | Rust rule engine |
| `getElement(rule)` | `RssRustRuleBridge.getElement` | 已替代 | Rust rule engine / platform diagnostics |
| `getElements(rule)` | `RssRustRuleBridge.getElements` | 已替代 | Rust rule engine / platform diagnostics |
| `put(key,value)` | Rust host `java.put` | 已替代 | Rust store |
| `get(key)` | Rust host `java.get` | 已替代 | Rust store |
| `evalJS(js,result)` | `RssRustRuleBridge.evalJS` | 已替代 | Rust/rquickjs |
| `ajax(url)` override | Rust host `java.ajax` | 已替代 | Rust request |
| `reGetBook()` | Rust host | 已替代 | `preUpdateJs` action |
| `refreshTocUrl()` | Rust host | 已替代 | `preUpdateJs` action |

## AnalyzeUrl 兼容方法 / 属性

| 原方法/属性 | 是否已替代 | 说明 |
|---|---:|---|
| `ruleUrl` | 已替代 | Rust URL host 可读写 |
| `url` | 已替代 | Rust 解析后 URL |
| `type` | 已替代 | URL option type |
| `headerMap` | 已替代 | Rust header map |
| `urlNoQuery` | 已替代 | Rust 内部解析 |
| `serverID` | 已替代 | `resolveUrl` 输出 |
| `initUrl()` | 已替代 | Rust 重新解析 URL 规则 |
| `evalJS(js,result)` | 已替代 | Rust/rquickjs |
| `put(key,value)` | 已替代 | Rust store |
| `get(key)` | 已替代 | Rust store |
| `getHeaderMap()` | 已替代 | Rust header map |
| `getStrResponseAwait()` / `getStrResponse()` | 已替代 | Rust text response |
| `getResponseAwait()` / `getResponse()` | 已替代 | Rust response wrapper |
| `getErrResponse()` / `getErrStrResponse()` | 已替代 | Rust error response wrapper |
| `getByteArrayAwait()` / `getByteArray()` | 已替代 | Rust raw bytes |
| `getInputStreamAwait()` / `getInputStream()` | 已替代-兼容包装 | Kotlin `ByteArrayInputStream` 包装 Rust bytes |
| `upload(fileName,file,contentType)` | 已替代 | Rust direct-link upload |
| `getGlideUrl()` | 已替代-平台边界 | Rust URL/header，Android Glide object |
| `getUserAgent()` | 已替代 | Rust UA 合并 |
| `isPost()` | 已替代 | Rust URL resolve method |
| `getMediaItem()` | 已替代-平台边界 | Rust URL/header，Android media object |
| `getMediaRequest()` | 已替代-平台边界 | Rust URL/header，Android media request |

## Java/Rhino/包兼容函数

| 函数/对象 | 是否已替代 | 说明 |
|---|---:|---|
| `JavaImporter(...)` | 已替代 | Rust 支持 direct-HTTP 常用导入 |
| `getClass(value)` | 已替代 | Rust class-like wrapper / 不支持项诊断 |
| `Packages.java.util.Collections.reverse(list)` | 已替代 | Rust prelude |
| `Packages.java.lang.Thread.sleep(ms)` | 已替代 | Rust sleep |
| `Packages.java.net.URLEncoder.encode(...)` | 已替代 | Rust URL encode |
| `Packages.android.util.Base64.*` | 已替代 | Rust Base64 兼容 |
| `Packages.org.jsoup.Jsoup.parse/connect` | 已替代 | Rust JSoup 兼容子集 |
| `Packages.com.jayway.jsonpath.JsonPath.*` | 已替代 | Rust JsonPath 兼容子集 |
| `Packages.javax.crypto.*` | 已替代 | Rust crypto 兼容常见 AES/HMAC/Cipher 路径 |
| `Packages.java.io.ByteArrayInputStream/OutputStream` | 已替代 | Rust byte wrapper |
| 未知 `Packages.*` / Android 专有包 | 已替代-平台边界 | 不能安全表达时 fail-fast，不恢复 JVM bridge |

## 仍应保留在 Android/Kotlin 的函数

这些函数不是 Rust 内部替代目标，只应作为 platform host 或结果适配层存在：

| 函数/区域 | 状态 | 说明 |
|---|---:|---|
| `SourceLoginJsExtensions.upUiData/reUiView/showBrowser/open` | 平台边界 | 登录 UI 和页面跳转 |
| `RssJsExtensions.searchBook/addBook/showPhoto/open` | 平台边界 | RSS 阅读 UI 动作 |
| `RustAnalyzerBridge.resolveMediaItem/resolveMediaRequest` 的对象创建部分 | 平台边界 | ExoPlayer/Android object |
| `RustAnalyzerBridge.applyCookieToWebView` 的 `CookieManager` 部分 | 平台边界 | WebView cookie |
| `Book` / `BookChapter` / `SearchBook` / `RssArticle` 转换函数 | 不适用 | Android 数据模型适配 |
| `RustJsHttpResponse` / `RustConnectionResponse` / `RustFile` | 已替代-兼容包装 | 保留给 Kotlin 调用点的形态兼容，底层不应重新实现 HTTP/文件逻辑 |

## 切除要求

1. 新增 direct-HTTP 能力时优先补 Rust analyzer，不在 Kotlin 新增规则预处理、HTTP helper 或 Rhino 兼容层。
2. Kotlin 只保留 Android 平台动作、UniFFI 调用和 Android 数据对象适配。
3. 能由 Rust 表达的 `java.*`、`source.*`、`cache.*`、`cookie.*`、`book.*`、`chapter.*`、AnalyzeRule、AnalyzeUrl API，不应再添加 Kotlin 实现分支。
4. WebView/browser/media/UI 类 API 必须通过 Rust platform action 连接 Android；没有 host 或参数无法安全表达时，Rust 必须 fail-fast 并带 source/rule/request/API 诊断。
