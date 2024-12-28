# PWOSPF Router Implementation

## 📋 Table of Contents
* [Overview](#overview)
* [Project Objectives](#project-objectives)
* [Features](#features) *(To be completed)*
* [Technical Architecture](#technical-architecture) *(To be completed)*
* [Getting Started](#getting-started) *(To be completed)*
* [Implementation Details](#implementation-details) *(To be completed)*
* [Testing and Validation](#testing-and-validation) *(To be completed)*
* [Contributing](#contributing) *(To be completed)*
* [License](#license) *(To be completed)*

## 🔍 Overview
This project implements a Pee-Wee OSPF (PWOSPF) router, a simplified version of the OSPF (Open Shortest Path First) routing protocol. PWOSPF is designed as a link-state routing protocol that enables routers to dynamically discover network topology, compute optimal paths, and adapt to network changes in real-time.

The implementation builds upon a basic router framework to create a fully functional dynamic routing system that can:
* Automatically discover neighboring routers
* Exchange network topology information
* Compute optimal paths to destinations
* Handle network failures and recoveries
* Maintain routing tables dynamically

## 🎯 Project Objectives

### Primary Objectives

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

### Technical Requirements

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

---
*[Additional sections to be completed in subsequent updates]*
