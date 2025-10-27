# How the Internet Works

## Volume 1: Core Infrastructure

*Generated: October 05, 2025*

---

## Table of Contents

1. [Understanding What the Internet Actually Is](#understanding-what-the-internet-actually-is)
2. [Physical Infrastructure Layer](#physical-infrastructure-layer)
3. [Network Hardware Infrastructure](#network-hardware-infrastructure)

---

## Understanding What the Internet Actually Is

The internet is fundamentally a "network of networks" - millions of independent networks choosing to interconnect and exchange data using common protocols. No single entity owns or controls the internet; instead, it operates through voluntary adoption of standards and cooperative agreements between network operators. This decentralized architecture is what makes the internet resilient, scalable, and resistant to censorship or control.

At its core, the internet implements packet switching, where data is broken into small chunks (packets) that travel independently across the network and are reassembled at their destination. This is fundamentally different from older circuit-switched networks like traditional telephone systems, where a dedicated connection was established for the duration of communication. Packet switching allows multiple conversations to share the same infrastructure efficiently, making the internet economically viable and massively scalable.

The internet operates on a layered protocol model, primarily TCP/IP (Transmission Control Protocol/Internet Protocol), where each layer handles specific aspects of communication. This layered approach means changes can be made at one layer without affecting others - for instance, upgrading from copper to fiber optic cables doesn't require changes to web browsers or email programs. This separation of concerns has allowed the internet to evolve continuously while maintaining backward compatibility.

The economic model of the internet is based on peering (free traffic exchange between networks of similar size) and transit (smaller networks paying larger ones for connectivity). This creates a natural hierarchy from small local ISPs through regional networks to massive Tier 1 providers that form the internet's backbone. These economic relationships, combined with technical protocols, create the seamless global network we experience.


---

## Physical Infrastructure Layer

The physical infrastructure of the internet is a vast, complex system spanning the entire globe. It includes everything from massive undersea cables connecting continents to the Wi-Fi router in your home. This infrastructure represents trillions of dollars of investment and decades of construction, yet most of it remains invisible to users.

### The Global Cable Network

The backbone of the internet consists of fiber optic cables that can carry terabits of data per second using light pulses. These cables form a mesh topology where multiple paths exist between major points, ensuring redundancy - if one cable is damaged, data automatically routes around the problem. The global cable infrastructure is owned by various entities including telecommunications companies, governments, and consortiums of companies who share construction and maintenance costs.

**Fiber Optic Technology:**

Fiber optic cables work by transmitting data as pulses of light through strands of glass thinner than human hair. The physics of total internal reflection keeps light trapped within the fiber, allowing it to travel tens of kilometers without significant loss. Modern fiber systems use multiple wavelengths of light simultaneously (wavelength division multiplexing), allowing a single fiber to carry dozens or hundreds of separate data channels.

- **Single-mode fiber**: Uses laser light traveling in a single path
  - Core diameter: 8-10 micrometers (smaller than a red blood cell)
  - Used for long-distance transmission (up to 100km without amplification)
  - Can carry 400 Gbps per wavelength, with 80+ wavelengths per fiber
  - Total capacity: 30+ Tbps per fiber pair

- **Multi-mode fiber**: Light travels in multiple paths
  - Core diameter: 50-62.5 micrometers
  - Used for shorter distances (up to 2km)
  - Less expensive equipment but limited distance
  - Common in data centers and campus networks

- **DWDM** (Dense Wavelength Division Multiplexing):
  - Splits light into 80+ channels at different wavelengths
  - Each wavelength carries independent data stream
  - Like having 80 different colored lasers in one fiber
  - Spacing between wavelengths: 0.8 nanometers (100 GHz) or less

**Submarine Cable Systems:**

Undersea cables are engineering marvels that carry 99% of intercontinental internet traffic (satellites handle less than 1%). These cables must withstand immense pressure, ship anchors, earthquakes, and marine life while operating for 25+ years. The investment required is enormous - a trans-Pacific cable system costs $300-500 million.

- **Cable construction**: Multiple layers of protection
  - Center: 8-16 fiber pairs in steel tube
  - Copper conductor: Carries 10,000 volts DC to power repeaters
  - Steel wire armoring: Protection from fishing trawlers
  - Polyethylene sheath: Waterproofing
  - Total diameter: 17-21mm (deep sea) to 50mm (shore landing)

- **Repeaters/Amplifiers**: Required every 60-100km
  - Erbium-doped fiber amplifiers (EDFAs) boost optical signal
  - Powered by constant current from shore stations
  - Designed for 25-year lifespan without maintenance
  - Use redundant components since repair requires expensive ships

- **Cable landing stations**: Where submarine cables reach land
  - Highly secure facilities (critical infrastructure)
  - Power feed equipment for submarine repeaters
  - Optical line terminating equipment
  - Connection to terrestrial networks

- **Maintenance and repair**:
  - Cable ships on standby in strategic locations
  - Typical repair time: 1-2 weeks
  - Use ROVs (remotely operated vehicles) in deep water
  - Grappling hooks retrieve cable from ocean floor

**Terrestrial Backbone Networks:**

Land-based fiber networks follow predictable paths along highways, railways, and utility rights-of-way. These networks are easier to maintain than submarine cables but face their own challenges including construction permits, weather damage, and accidental cuts during construction work.

- **Dark fiber**: Unused fiber capacity installed for future use
  - Installing fiber is expensive; adding extra strands is cheap
  - "Dark" because no light signals are transmitted
  - Can be leased and "lit" when needed
  - Major routes have hundreds of fiber strands

- **Optical amplification**: Boosting signals for long-distance transmission
  - EDFAs every 80-120km on terrestrial routes
  - Raman amplification for ultra-long spans
  - Optical-electrical-optical (OEO) regeneration for signal cleanup

- **Network topology**: How backbone networks are structured
  - Ring topology: Provides automatic backup path
  - Mesh topology: Multiple paths between points
  - Dual-diverse routing: Two completely separate physical paths

### Last Mile Infrastructure

The "last mile" (or "first mile" from the user's perspective) is often the bottleneck in internet connectivity. While backbone networks have massive capacity, getting that capacity to individual homes and businesses is expensive and technically challenging. Different technologies serve different population densities and geographic conditions.

**DSL (Digital Subscriber Line):**

DSL technology cleverly reuses existing telephone infrastructure by transmitting data at frequencies above those used for voice calls. This allows internet and phone service to work simultaneously on the same copper wire. While slower than newer technologies, DSL's advantage is that phone lines already reach nearly every building in developed countries.

- **ADSL** (Asymmetric DSL): Different upload/download speeds
  - Download: 1-24 Mbps, Upload: 0.5-3 Mbps
  - Distance sensitive: Speed decreases with distance from DSLAM
  - Maximum range: 5.5km from telephone exchange
  - Uses frequency division: 0-4kHz (voice), 25-138kHz (upload), 138kHz-1.1MHz (download)

- **VDSL/VDSL2** (Very-high-bit-rate DSL):
  - Up to 100 Mbps download, 50 Mbps upload
  - Maximum range: 1.5km (much shorter than ADSL)
  - Uses frequencies up to 30MHz
  - Often deployed as FTTC (Fiber to the Cabinet) with VDSL for final connection

- **G.fast**: Latest DSL technology
  - Up to 1 Gbps over very short distances (<100m)
  - Uses frequencies up to 106MHz or 212MHz
  - Requires fiber very close to premises

- **Vectoring**: Reduces interference between lines
  - DSL lines in same bundle interfere with each other (crosstalk)
  - Vectoring uses signal processing to cancel interference
  - Can double speeds in ideal conditions

**Cable Internet (DOCSIS):**

Cable internet uses the same coaxial cables that deliver cable television, sharing bandwidth among neighbors in a local area. DOCSIS (Data Over Cable Service Interface Specification) is the standard that allows data transmission over cable TV infrastructure. Unlike DSL, cable internet is a shared medium where neighborhood usage affects individual speeds.

- **DOCSIS 3.0**: Current widespread deployment
  - Channel bonding: Combines multiple 6MHz channels
  - 32 downstream × 8 upstream channels typical
  - Theoretical maximum: 1 Gbps down, 200 Mbps up
  - Real-world: 100-400 Mbps typical

- **DOCSIS 3.1**: Latest standard
  - OFDM (Orthogonal Frequency Division Multiplexing) for better spectral efficiency
  - Up to 10 Gbps downstream, 1-2 Gbps upstream
  - Low Latency DOCSIS (LLD) for gaming and video calls
  - Backward compatible with DOCSIS 3.0

- **HFC** (Hybrid Fiber-Coaxial) architecture:
  - Fiber from headend to neighborhood node
  - Coaxial cable for last few hundred meters
  - Node serves 100-2000 homes
  - Node splitting to reduce congestion

- **Signal challenges**:
  - Ingress noise: External RF interference entering system
  - Return path noise: Cumulative noise from all homes
  - Amplifier cascade: Each amplifier adds noise and distortion

**Fiber to the Home (FTTH/FTTP):**

Fiber to the home represents the gold standard for internet connectivity, offering virtually unlimited bandwidth potential. However, installation costs are high, particularly in areas with existing underground utilities or low population density. Various architectures balance cost and performance.

- **PON** (Passive Optical Network): Most common FTTH technology
  - No powered equipment between central office and customer
  - Optical splitters divide signal among users (passive = no power required)
  - Single fiber can serve 32-128 homes
  - Lower cost than active Ethernet

- **GPON** (Gigabit PON): ITU-T G.984 standard
  - 2.488 Gbps downstream, 1.244 Gbps upstream
  - Split among up to 64 users
  - 20km maximum reach
  - Uses different wavelengths for up/down (1490nm down, 1310nm up)

- **XGS-PON**: 10 Gigabit symmetric PON
  - 10 Gbps both directions
  - Coexists with GPON on same fiber (different wavelengths)
  - Future-proof for decades

- **Active Ethernet**: Dedicated fiber per customer
  - Point-to-point connection (no sharing)
  - 1-10 Gbps typical, 100 Gbps possible
  - More expensive but guaranteed bandwidth
  - Common in business installations


---

## Network Hardware Infrastructure

The internet's routing infrastructure consists of millions of devices working together to forward packets toward their destinations. These range from massive core routers handling terabits per second to home routers managing a single family's devices. Each router makes independent forwarding decisions, creating a resilient system with no single point of failure.

### Core Routers

Core routers form the backbone of the internet, handling massive amounts of traffic at major interconnection points. These are room-sized systems costing millions of dollars, designed for maximum throughput and reliability. They must process packets in nanoseconds while maintaining routing tables with nearly a million entries.

- **Architecture**: Modular chassis with replaceable components
  - Route processor: Manages routing protocols and tables
  - Line cards: Interface modules for fiber connections
  - Switch fabric: Interconnects line cards at terabit speeds
  - Redundant everything: Power, fans, processors

- **Performance specifications**:
  - Throughput: 100+ Tbps switching capacity
  - Port density: Hundreds of 100/400 Gbps ports
  - Packet forwarding: Billions of packets per second
  - Latency: Microseconds through the router

- **Routing table management**:
  - BGP table: ~950,000 routes (and growing)
  - FIB (Forwarding Information Base): Optimized lookup table
  - TCAM (Ternary Content Addressable Memory): Hardware-accelerated lookups
  - Route aggregation to reduce table size

- **Major vendors**: Cisco, Juniper, Huawei, Nokia (Alcatel-Lucent)
  - Custom ASICs for packet processing
  - Proprietary and open operating systems
  - SDN (Software-Defined Networking) capabilities

### Internet Exchange Points (IXPs)

IXPs are physical locations where different networks connect to exchange traffic. They're critical to internet performance and economics, allowing networks to exchange traffic locally rather than routing through distant third parties. Major IXPs handle more traffic than entire countries.

- **Physical infrastructure**:
  - Meet-me rooms: Secure spaces for network interconnection
  - Cross-connects: Physical cables between networks
  - Switching fabric: Typically Ethernet switches for peering
  - Route servers: Optional centralized routing

- **Major global IXPs**:
  - DE-CIX Frankfurt: 10+ Tbps peak traffic
  - AMS-IX Amsterdam: 8+ Tbps peak
  - IX.br São Paulo: Largest in Southern Hemisphere
  - LINX London: 5+ Tbps peak

- **Peering types**:
  - Bilateral peering: Direct connection between two networks
  - Multilateral peering: Via route server to many networks
  - Private peering: Dedicated fiber between networks
  - Public peering: Shared switching infrastructure

- **Economics**: Cost savings and performance benefits
  - Avoid transit costs for local traffic
  - Reduce latency by keeping traffic local
  - Improve reliability with direct connections
  - Monthly port fees: $500-10,000 depending on speed

### Data Center Infrastructure

Data centers are the factories of the digital economy, housing the servers that power everything from Google searches to Netflix streams. Modern hyperscale data centers are engineering marvels, consuming as much power as small cities while maintaining 99.999% uptime. The concentration of computing power requires sophisticated cooling, power, and networking infrastructure.

**Physical Design and Construction:**

Data center design balances numerous competing requirements: power efficiency, cooling capacity, network connectivity, physical security, and disaster resistance. Location selection considers power availability, network connectivity, natural disaster risk, and local regulations. Modern data centers are increasingly built in cold climates or near renewable energy sources.

- **Building specifications**:
  - Size: 100,000-1,000,000+ square feet
  - Power: 10-200+ MW capacity
  - Raised floors: 2-4 feet for cooling and cables
  - Ceiling height: 12-20 feet for hot air return
  - Floor loading: 150-350 pounds per square foot
  - Seismic bracing in earthquake zones

- **Security layers**:
  - Perimeter fencing with intrusion detection
  - Vehicle barriers and inspection points
  - Biometric access controls
  - Mantrap entries (security airlocks)
  - 24/7 security staff and CCTV
  - Separate cages for different customers

**Power Systems:**

Data centers require massive amounts of reliable power. A single hyperscale facility can consume 100+ MW - enough to power 80,000 homes. Power systems must provide uninterrupted service even during grid failures, with redundancy at every level.

- **Utility power delivery**:
  - Multiple feeds from different substations
  - Medium voltage (13.8kV-35kV) service
  - On-site substations for voltage step-down
  - Power factor correction equipment

- **UPS** (Uninterruptible Power Supply) systems:
  - Battery: 5-30 minutes runtime at full load
  - Flywheel: 15-30 seconds for generator start
  - Types: Online double-conversion for best protection
  - Efficiency: 94-97% in eco-mode
  - Modular designs for maintenance without downtime

- **Backup generators**:
  - Diesel most common (natural gas in some locations)
  - 2-3 MW per generator typical
  - N+1, N+2, or 2N redundancy
  - 24-72 hours fuel on-site
  - Monthly testing required
  - Emissions regulations limit runtime

- **Power distribution**:
  - PDUs (Power Distribution Units) in server racks
  - Automatic transfer switches (ATS)
  - Remote power panels (RPP)
  - Busway systems for flexibility
  - Monitoring at circuit level

**Cooling Systems:**

Cooling represents 30-50% of data center energy consumption. Modern facilities use sophisticated techniques to minimize cooling costs while maintaining safe operating temperatures. The trend is toward higher operating temperatures and free cooling where climate permits.

- **CRAC/CRAH** (Computer Room Air Conditioning/Handler):
  - CRAC: Direct expansion (DX) cooling with refrigerant
  - CRAH: Chilled water from central plant
  - Capacity: 30-150 tons per unit
  - Placement: Perimeter or in-row

- **Hot aisle/Cold aisle configuration**:
  - Servers face each other across cold aisles
  - Exhaust hot air into hot aisles
  - Containment systems prevent mixing
  - Temperature differential: 20-30°F

- **Liquid cooling**: For high-density deployments
  - Rear-door heat exchangers: Water-cooled doors on racks
  - Direct-to-chip: Cold plates on CPUs/GPUs
  - Immersion cooling: Servers submerged in dielectric fluid
  - Can handle 50+ kW per rack (vs 10-15kW air-cooled)

- **Free cooling**: Using outside air when cool enough
  - Airside economizers: Direct outside air
  - Waterside economizers: Cooling towers
  - Effective when outside temp <65°F
  - Can eliminate mechanical cooling 50-90% of year

**Network Architecture within Data Centers:**

Data center networks must handle massive east-west traffic (server to server) in addition to north-south traffic (to/from internet). Modern architectures use leaf-spine topologies for predictable performance and easy scaling.

- **Traditional three-tier architecture** (becoming obsolete):
  - Core: High-speed backbone switches
  - Aggregation: Middle layer for policy and services
  - Access: Top-of-rack switches connecting servers
  - Problems: Bottlenecks, complex spanning tree

- **Leaf-spine architecture** (modern standard):
  - Leaf switches: Connect to servers (48-64 ports typical)
  - Spine switches: Connect all leaf switches
  - Every leaf connects to every spine
  - Predictable latency: Always two hops between servers
  - Easy scaling: Add spines for bandwidth, leaves for servers

- **Speeds and feeds**:
  - Server connections: 10/25/50/100 Gbps
  - Leaf-spine links: 40/100/400 Gbps
  - Oversubscription ratios: 3:1 typical (3Gbps server traffic, 1Gbps uplink capacity)

- **SDN in data centers**:
  - Centralized control plane
  - Programmable forwarding
  - Dynamic load balancing
  - Microsegmentation for security


---
