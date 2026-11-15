# cache-isolation-audit

Node.js 缓存隔离审计库：给定请求特征、源站响应策略和 CDN 缓存键规则，
判断两个不同用户的请求是否可能命中同一个缓存对象，并输出冲突请求对的
规范缓存键（canonical cache key）。

## 使用

```js
import { auditIsolation } from './index.js';

const result = auditIsolation({
  requests: [
    { id: 'a', user: 'alice', host: 'example.com', path: '/account',
      query: '', cookie: 'session=alice-token', headers: {} },
    { id: 'b', user: 'bob', host: 'example.com', path: '/account',
      query: '', cookie: 'session=bob-token', headers: {} },
  ],
  origin: {
    protected: true,                      // 资源需要鉴权
    cacheControl: 'public, max-age=300',  // 源站 Cache-Control
    vary: ['Cookie'],                     // 源站 Vary
  },
  cdn: {
    includeHost: true,
    path: { dotSegments: true, collapseDoubleSlashes: true,
            caseSensitive: true, decodeUnreserved: true },
    query: { mode: 'all', params: [], sort: true },
    cookies: [],            // CDN 计入键的 Cookie 名
    headers: [],            // CDN 计入键的请求头
    varyHandling: 'origin', // 'origin' | 'merge' | 'override' | 'ignore'
    varyOverride: [],
  },
});
// result.findings  — 风险项（含严重级别与说明）
// result.conflicts — 跨用户冲突对，含规范缓存键 key 与 components
// result.keys      — 每个请求的规范键
```

## 识别的风险

- `PROTECTED_RESOURCE_CACHEABLE`：受保护资源可被共享缓存存储
- `AUTH_CONTEXT_MISSING`：Authorization 未进入缓存键或有效 Vary
- `SENSITIVE_COOKIE_MISSING`：敏感 Cookie 未计入缓存键
- `VARY_MERGE_ERROR`：CDN 忽略或覆盖源站 Vary，丢失键维度
- `PATH_ENCODING_INCONSISTENCY`：不同原始路径归一化后相同
- `IGNORED_SECURITY_PARAM`：安全相关查询参数（token、sig、uid 等）被键规则忽略
- `HOST_COLLISION`：Host 未计入键但请求跨多个虚拟主机
- `CROSS_USER_CACHE_HIT`：不同用户产生相同规范键（冲突对附规范键）

## 分析依赖的 CDN 假设

1. **共享缓存语义**：CDN 遵循 HTTP 共享缓存规则——`private`/`no-store`
   不存储，`public` 或正的 `max-age`/`s-maxage` 可存储；鉴权本身的正确性
   不在审计范围内，只审计键的区分能力。
2. **键由可配置维度组成**：Host、归一化路径、查询参数（全部/白名单/
   黑名单/忽略）、指定 Cookie、指定请求头，以及按 `varyHandling` 处理后的
   Vary 维度。两个请求的键字符串完全相等即判定可能命中同一对象。
3. **路径归一化按 RFC 3986**：点段按 5.2.4 移除，双斜杠可折叠，仅解码
   非保留字符的百分号编码（`%2F` 等保留字符编码永不折叠为路径分隔符），
   大小写敏感性可配置。假设源站与 CDN 归一化不一致是攻击面之一。
4. **查询串保序解析**：重复参数名保留全部值及相对顺序；排序仅用于键的
   规范化，不改变同名重复值的先后。
5. **Cookie 解析**：同名 Cookie 可出现多次，全部值按序计入键；
   `Vary: Cookie` 视为钉住整个 Cookie 头。
6. **Host 归一化**：默认大小写不敏感并剥离默认端口（80/443）。
7. **Vary 合并模型**：`origin` 完全信任源站；`merge` 取并集；
   `override` 以 CDN 配置取代源站（丢失的源站条目报 `VARY_MERGE_ERROR`）；
   `ignore` 视为无任何 Vary 维度。

## 测试

```sh
node --test
```

覆盖点段路径、双斜杠、大小写、重复参数、Cookie 多值、Host 差异和
Vary 覆盖等场景。
