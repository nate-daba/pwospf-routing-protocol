# PWOSPF Router Implementation

## 📋 Table of Contents
* [Overview](#-overview)
* [Project Objectives](#-project-objectives)
* [Features](#-features)
* [Technical Architecture](#%EF%B8%8F-technical-architecture)
* [Implementation Details](#implementation-details) *(To be completed)*
* [Testing and Validation](#testing-and-validation) *(To be completed)*

## 🔍 Overview
This project implements a Pee-Wee OSPF (PWOSPF) router, a simplified version of the OSPF (Open Shortest Path First) routing protocol. PWOSPF is designed as a link-state routing protocol that enables routers to dynamically discover network topology, compute optimal paths, and adapt to network changes in real-time.

The implementation builds upon a basic router framework to create a fully functional dynamic routing system that can:
* Automatically discover neighboring routers
* Exchange network topology information
* Compute optimal paths to destinations
* Handle network failures and recoveries
* Maintain routing tables dynamically

## 🎯 Project Objectives

<details>
<summary><strong>Primary Objectives</strong></summary>

#### 1. Dynamic Route Discovery
Implement PWOSPF protocol to enable routers to:
* Build their own routing tables from link-state routing messages
* Detect link failures and recovery automatically
* Exchange routing information with neighboring routers

#### 2. Network Topology Management
* Maintain a complete view of the network topology
* Handle topology changes through link-state updates
* Support a multi-router environment with dynamic neighbor discovery

#### 3. Routing Protocol Implementation
* Implement HELLO protocol for neighbor discovery and maintenance
* Develop Link State Update (LSU) mechanism for topology information exchange
* Create efficient shortest path computation for routing decisions
</details>

<details>
<summary><strong>Technical Requirements</strong></summary>

#### 1. Protocol Specifications
* PWOSPF Version 2 compatibility
* Support for broadcast HELLO messages (every 10 seconds by default)
* Link State Updates (LSU) transmission (every 30 seconds by default)
* Proper handling of protocol headers and checksums

#### 2. Routing Features
* Support for static and dynamic routes
* Handling of directly connected subnets
* Default route management
* Subnet-based routing with proper mask handling

#### 3. Fault Tolerance
* Detection of neighbor timeouts (3× HELLO interval)
* Link failure and recovery handling
* Topology database maintenance and cleanup
* Route recomputation on network changes
</details>

## ⚡ Features

<details>
<summary><strong>Core Routing Capabilities</strong></summary>

* **Dynamic Routing Table Construction**
  * Automatic building of routing tables from link-state messages
  * Support for both static and dynamic routes
  * Intelligent handling of directly connected subnets
  * Default route management for internet connectivity
</details>

<details>
<summary><strong>Protocol Implementation</strong></summary>

* **HELLO Protocol**
  * Periodic broadcast of HELLO messages (10-second intervals)
  * Dynamic neighbor discovery and maintenance
  * Automatic detection of neighbor timeouts (30-second threshold)
  * Real-time neighbor state tracking

* **Link State Updates (LSU)**
  * Periodic LSU broadcasts (30-second intervals)
  * Efficient flooding mechanism with loop prevention
  * Sequence number tracking for update ordering
  * TTL-based flood control
</details>

<details>
<summary><strong>Topology Management</strong></summary>

* **Network Discovery**
  * Complete topology database maintenance
  * Automatic detection of network changes
  * Bidirectional link verification
  * Support for multi-router environments

* **Fault Tolerance**
  * Automatic link failure detection
  * Dynamic recovery from network changes
  * Topology database cleanup for stale entries
  * Immediate route recomputation on topology changes
</details>

<details>
<summary><strong>Routing Algorithm & Protocol Specifications</strong></summary>

* **Path Computation**
  * Implementation of shortest path algorithm
  * Subnet-based routing decisions
  * Proper handling of subnet masks
  * Next-hop computation for optimal forwarding

* **PWOSPF v2 Compliance**
  * Standard-compliant packet formats
  * Proper checksum calculation and verification
  * Area-based routing (single area support)
  * Router ID management

* **IP Packet Handling**
  * Protocol number 89 (OSPF standard)
  * Support for broadcast addresses
  * Proper IP encapsulation
  * Checksum verification and generation
</details>

## 🏗️ Technical Architecture

<details>
<summary><strong>Network Topology</strong></summary>

The project is developed and tested on a specific network topology consisting of three virtual PWOSPF routers (vhost1, vhost2, and vhost3) interconnected via subnets. This topology demonstrates the router's capability to handle dynamic route discovery, link failures, and network changes.

![Network Topology](images/113.png)

Key aspects of the topology:

* Each link represents a subnet, with two IP addresses (one for each end)
* All three routers (vhost1, vhost2, and vhost3) run the PWOSPF protocol
* The gateway provides connectivity to the internet (CS department network)
* Two servers act as end hosts for testing connectivity
* vhost1 connects to the gateway and serves as the internet access point
* Each router has multiple interfaces with specific IP/subnet configurations
* The topology allows testing of various scenarios including:
  * Dynamic route discovery
  * Link failure detection
  * Path recomputation
  * Network recovery

This topology is used for both development and testing, though IP assignments may differ during evaluation to ensure no hardcoding of addresses in the implementation.
</details>

<details>
<summary><strong>System Components</strong></summary>

### Core Components
* **PWOSPF Subsystem**
  * Controls protocol operations and neighbor discovery
  * Manages link-state database and routing updates
  * Handles HELLO and LSU packet processing

* **Interface Manager**
  * Manages multiple network interfaces
  * Processes incoming/outgoing PWOSPF packets
  * Maintains interface states and neighbor relationships

* **Route Calculator**
  * Implements shortest path computation
  * Updates routing table based on topology changes
  * Handles dynamic and static route management
</details>

## 🚀 Implementation Details

The PWOSPF router is implemented in several core components and data structures, primarily within **`sr_pwospf.c`** and its related headers. The design follows a simplified link-state protocol that enables routers to discover neighbors, exchange topology information, and perform shortest path calculations. Key aspects include:

1. **PWOSPF Subsystem**
   - Maintains a `pwospf_subsys` data structure, storing the local router’s interfaces, topology database, and protocol state (e.g., sequence numbers for Link State Updates).
   - Spawns a dedicated PWOSPF thread (`pwospf_run_thread()`) to handle periodic tasks such as sending HELLO messages, checking neighbor timeouts, and sending periodic LSUs.

2. **HELLO Protocol**
   - **`send_pwospf_hello()`** constructs and broadcasts HELLO packets to the multicast address `224.0.0.5`.
   - **`handle_pwospf_hello()`** processes incoming HELLO packets, updating or adding neighbors in the PWOSPF interface list.
   - Neighbor lifetimes are monitored, and inactive neighbors are removed automatically.

3. **Link State Updates (LSU)**
   - **`pwospf_send_lsu()`** builds and sends LSU packets containing the router’s local links, neighbor IDs, and optional default route advertisements.
   - **`pwospf_handle_lsu()`** processes incoming LSUs, updating the router’s topology database and flooding the updates where necessary.
   - Topology changes trigger immediate route recomputation.

4. **Topology & Routing**
   - The topology is stored as a linked list of `pwospf_router` structures, each with interfaces describing subnets and neighbor links.
   - **`bfs_shortest_paths()`** performs a BFS-based shortest path computation, updating or creating routing table entries accordingly.
   - **`recalculate_routing_table()`** orchestrates the BFS process, clearing stale routes and adding new ones for updated subnets.

5. **Neighbor & Interface Management**
   - Each `pwospf_interface` tracks a single neighbor (for simplicity), storing its IP address and the last time a HELLO packet was received.
   - **`pwospf_check_on_neighbors()`** periodically checks for timed-out neighbors, removing them from the topology and triggering an LSU if necessary.

6. **Static Routes & Gateway**
   - **`read_static_routes()`** scans the initial routing table for default or static routes, marking the router as a gateway if a default route is found.
   - Gateway routers advertise `0.0.0.0/0` in their LSUs to inform others of a default path.

With these components, the system provides a complete yet simplified OSPF-like environment that adapts to network changes on the fly.


## 🧪 Testing and Validation

This project includes a script (**`test.sh`**) that verifies correct behavior under various scenarios. The tests aim to validate the PWOSPF router’s functionality, including route discovery, neighbor timeouts, link-state flooding, and end-to-end connectivity checks.

First, ssh into the server you want to run software router on.

```bash
ssh <username>@<server_ip>
```

Next, clone the repository and navigate to the project directory:

```bash
git clone https://github.com/nate-daba/pwospf-routing-protocol.git
cd pwospf-routing-protocol/pwospf_stub
```

Then follow the steps below to start the routers and run automated tests:

1. **Starting the Routers**
   - Open three separate ssh connections to the server and run the following commands to start the routers:

      - **Router 1 (vhost1) on ssh connection 1**:
        ```bash
        ./sr -t 113 -v vhost1 -r rtable.net
        ```
      - **Router 2 (vhost2) on ssh connection 2**:
        ```bash
        ../sr -t 113 -v vhost2 -r rtable.empty
        ```
      - **Router 3 (vhost3) on ssh connection 3**:
        ```bash
        ../sr -t 113 -v vhost3 -r rtable.empty
        ```
    

2. **Running Automated Tests**  
   - Use the **`-t`** option to specify a topology number. For example:
     ```bash
     ./test.sh -t 113
     ```
   - The script will look for a file named `vnltopo1.iplist` (or `vnltopoX.iplist`) containing IP assignments for the routers, servers, and gateway in that topology.

2. **Script Workflow**  
   1. **Ping Testing**  
      - For each IP address found in the `iplist` file (e.g., `ip_server1_eth0`, `ip_server2_eth0`, etc.), the script executes a series of pings (`ping -c 5`) to verify reachability.  
      - Successful replies confirm basic IP connectivity through the PWOSPF router.
   2. **HTTP Download**  
      - If server IPs are present, it attempts a file download (`wget http://SERVER_IP:16280/64MB.bin`) from both servers, ensuring TCP paths are established and traffic flows through the router.
   3. **Inter-Server Pings**  
      - The script then instructs each server to ping the other, validating that routes are correctly established in both directions.

3. **Validation Criteria**  
   - **Neighbor Discovery**: HELLO messages must be exchanged successfully, and neighbors appear in the topology.
   - **Route Computation**: Both direct and default routes are inserted correctly, and BFS-based computations generate minimal or optimal paths.
   - **Failure Handling**: If a link or neighbor times out, the routing table should converge to an updated valid state, and LSUs should propagate the topology change.
   - **Stability Under Load**: Download tests (`wget`) verify that standard TCP flows remain stable and are properly routed.

4. **Interpreting Test Results**  
   - **Ping Outputs**: Consistent `0% packet loss` indicates valid paths. Failure implies a missing or incorrect route.  
   - **Download Results**: Any HTTP file retrieval success from servers behind the router further validates end-to-end connectivity.  
   - **Server-to-Server**: If servers can ping each other via the PWOSPF router(s), multi-hop routing is confirmed functional.

By following these tests and verifying logs, pings, and routing-table outputs, you can ensure the PWOSPF router meets all major requirements set forth in the project specification.
