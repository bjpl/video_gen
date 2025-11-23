# How the Internet Works

## Supplementary Guide: Additional Technical Content

*Generated: October 05, 2025*

---

## Table of Contents

1. [Content Delivery and Optimization](#content-delivery-and-optimization)
2. [Web Performance Optimization](#web-performance-optimization)
3. [HTTP Caching](#http-caching)
4. [Advanced Networking Protocols](#advanced-networking-protocols)
5. [IoT and Modern Technologies](#iot-and-modern-technologies)

---

## Content Delivery and Optimization

The modern internet must deliver massive amounts of content - from 4K video streams to complex web applications - quickly and efficiently to billions of users. This requires sophisticated systems for caching, content distribution, and optimization.

### Content Delivery Networks (CDNs)

CDNs revolutionized internet content delivery by distributing content to servers near users. Instead of every request going to a single origin server, CDNs serve content from nearby edge locations.

**CDN Architecture**:
Modern CDNs consist of thousands of servers in hundreds of locations worldwide. They use sophisticated algorithms to route users to optimal servers based on geography, network conditions, and server load.

Points of Presence (PoPs): CDN locations
- Edge servers: Serve cached content
- Located in major cities and IXPs
- Typical CDN: 100-300 PoPs globally
- Each PoP: Multiple servers for redundancy
- Interconnection: Peering with ISPs

Content distribution:
- Push: Origin actively sends to edges
- Pull: Edges fetch on first request
- Prefetching: Predictive caching
- Tiered architecture:
  - Edge servers: Close to users
  - Regional caches: Intermediate layer
  - Origin shield: Protects origin server

Request routing: Getting users to right server
- DNS-based: Most common
  - CDN controls DNS for content domain
  - Returns IP of nearby edge server
  - TTL controls routing granularity
- Anycast: Same IP everywhere
  - BGP routes to nearest location
  - Fast failover but less control
- HTTP redirect: Application-level
  - 302 redirect to optimal server
  - Higher latency but precise control

### Caching Strategies

Effective caching is crucial for CDN performance. Different content types require different caching strategies.

Cache control headers:
- Cache-Control: Primary caching directive
  - max-age: Seconds until stale
  - no-cache: Validate before use
  - no-store: Never cache
  - private/public: User-specific vs shared
- ETag: Content fingerprint
  - Validates if content changed
  - Conditional requests with If-None-Match
- Last-Modified: Timestamp validation

Cache invalidation: Removing stale content
- TTL expiration: Natural timeout
- Purge: Immediate removal
- Soft purge: Mark stale, serve while updating
- Tag-based: Invalidate by category

Dynamic content caching:
- Edge Side Includes (ESI): Assemble at edge
- Cache key customization: Vary by parameters
- Micro-caching: Short TTLs for dynamic content

## Web Performance Optimization

Web performance directly impacts user experience and business metrics. Modern web performance optimization involves dozens of techniques working together.

### Critical Render Path Optimization

The critical render path is the sequence of steps browsers take to display a page.

Resource loading:
- Parser blocking: CSS and JavaScript
- Async/defer JavaScript:
  - Async: Download parallel, execute when ready
  - Defer: Download parallel, execute after parsing
- Preloading: Critical resources
  - Fonts, critical CSS, important images
- DNS prefetch: Resolve domains early
- Preconnect: Establish connections early

CSS optimization:
- Critical CSS: Inline above-fold styles
- Remove unused CSS: Tree shaking
- CSS containment: Limit reflow scope
- CSS Grid/Flexbox: Efficient layouts

JavaScript optimization:
- Code splitting: Load what's needed
- Tree shaking: Remove dead code
- Minification: Remove whitespace
- Bundle optimization: Reduce requests
- Service workers: Offline and caching

### Image and Media Optimization

Images and video constitute the majority of web traffic.

Modern image formats:
- WebP: 25-35% smaller than JPEG
- AVIF: 50% smaller than JPEG
- JPEG XL: Better compression, progressive
- Format selection: Picture element for responsive images

Responsive images:
- srcset: Multiple resolutions
- sizes: Viewport-based selection
- Art direction: Different crops
- Lazy loading: Load when visible

Video optimization:
- Adaptive bitrate streaming:
  - HLS: Apple's HTTP Live Streaming
  - DASH: Dynamic Adaptive Streaming
  - Multiple quality levels
  - Switches based on bandwidth
- Modern codecs:
  - H.265/HEVC: 50% better than H.264
  - VP9: Google's codec
  - AV1: Open, royalty-free

## HTTP Caching

HTTP caching occurs at multiple levels - browser cache, proxy caches, and CDN caches.

### Browser Caching

Browsers maintain sophisticated caches that store resources locally.

Cache storage:
- Memory cache: RAM, fastest
- Disk cache: Persistent storage
- Service worker cache: Programmable
- Size limits: Vary by browser
- Eviction: LRU when full

Validation mechanisms:
- Strong validation: ETag comparison
- Weak validation: Last-Modified
- 304 Not Modified: No body sent
- Conditional requests save bandwidth

Cache hierarchies:
- Browser cache: First check
- Service worker: Programmable layer
- HTTP cache: Standard caching
- Push cache: HTTP/2 pushed resources

### Proxy and Gateway Caching

Intermediate caches between clients and servers can dramatically reduce origin load.

Forward proxy caching: Client-side
- Corporate proxies: Shared cache
- ISP transparent proxies: Controversial
- Benefits: Reduced bandwidth
- Issues: Privacy, HTTPS bypasses

Reverse proxy caching: Server-side
- Varnish, nginx, HAProxy
- Shields origin from load
- Application-aware caching
- Cache warming: Preload content

## Advanced Networking Protocols

### HTTP/3 and QUIC

HTTP/3 represents the biggest change to HTTP since HTTP/1.1. Built on QUIC instead of TCP, it solves fundamental performance problems that have plagued web performance for decades.

Why QUIC beats TCP:
- No head-of-line blocking: Packet loss doesn't block other streams
- 0-RTT connections: Instant resumption
- Connection migration: Survives IP changes
- Better congestion control: Per-stream flow control
- Always encrypted: Security built-in

Deployment challenges:
- UDP blocking: Some networks block UDP
- Middlebox interference: Firewalls, NATs
- CPU overhead: More processing than TCP
- Fallback required: Must support HTTP/2

Performance improvements:
- 15-20% faster page loads average
- 30%+ improvement on lossy networks
- Better mobile performance
- Reduced bufferbloat impact

## IoT and Modern Technologies

### IoT Networking Protocols

Traditional internet protocols often don't work for IoT devices with limited power and processing. Specialized protocols optimize for IoT constraints.

MQTT (Message Queue Telemetry Transport):
- Publish/subscribe model
- Minimal overhead (2-byte header)
- QoS levels: At most once, at least once, exactly once
- Persistent sessions
- Last will messages
- Ideal for sensors

CoAP (Constrained Application Protocol):
- Like HTTP but for constrained devices
- Uses UDP instead of TCP
- 4-byte header vs HTTP's dozens
- Multicast support
- Observable resources

LoRaWAN: Long-range, low-power
- 10+ km range in rural areas
- 10-year battery life possible
- 0.3-50 kbps data rates
- Unlicensed spectrum

### IoT Security Challenges

IoT devices pose unique security challenges - they're often poorly secured, rarely updated, and deployed for years. Compromised IoT devices have been used in massive DDoS attacks.

Common vulnerabilities:
- Default passwords never changed
- No update mechanism
- Unencrypted communications
- Exposed management interfaces
- No secure boot

Security approaches:
- Network segmentation: Isolate IoT devices
- Gateway security: Filter at edge
- Device identity: Certificates from manufacture
- Secure elements: Hardware security
- Automatic updates: Critical but rare

### Edge Computing Architecture

Edge computing creates a hierarchy of processing locations from centralized clouds to devices themselves. Different applications use different levels based on latency and processing requirements.

Edge locations:
- Regional edge: Major metro areas
- Network edge: ISP facilities
- On-premise edge: Enterprise locations
- Device edge: Processing on device

Use cases:
- AR/VR: Rendering at edge
- Autonomous vehicles: Local decision making
- Video analytics: Process at camera
- Gaming: Reduce latency
- IoT processing: Filter before sending

Technologies enabling edge:
- 5G networks: Built-in edge computing
- WebAssembly: Portable edge functions
- Kubernetes: Orchestration at edge
- FPGAs: Hardware acceleration

---

*This supplementary guide provides additional technical details not covered in the main volumes. For the complete picture of how the internet works, refer to all volumes in this series.*
