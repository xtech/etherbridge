# **EtherBridge - A Transparent Ethernet Tunnel for Robotics**

## **Overview**
EtherBridge is a lightweight C++ networking tool that enables seamless debugging and communication with a robot's internal Ethernet network from an external host. This is achieved by creating a virtual network interface on the host that transparently bridges communication to the robot's internal network, even when the robot is connected to an external Wi-Fi network.

## **How It Works**
The system consists of two main components:

1. **EtherBridge Server (Running on the Robot)**
    - Listens for incoming UDP connections on port `5432` via the robot's Wi-Fi interface.
    - Establishes a Layer 2 connection to the robot's internal Ethernet network.
    - Forwards packets bidirectionally between the UDP connection and the internal network.

2. **EtherBridge Client (Running on the Debugging Host)**
    - Creates a TAP (virtual network) device on the host machine with a user-defined IP.
    - Connects to the EtherBridge Server using UDP.
    - Sends and receives Ethernet frames, making it appear as if the host is directly connected to the robot's internal network.

With this setup, developers can access the robot's internal sensors and actuators from their host machine without requiring a physical wired connection.

## **Features**
- **Transparent Layer 2 Bridging:** The host machine can communicate with the robot's internal network as if it were physically connected.
- **UDP Tunneling:** Uses UDP for efficient and low-latency network bridging.
- **TAP Device Integration:** The client creates a virtual network device on the host for seamless packet forwarding.
- **No Changes to Internal Network:** The robot's internal DHCP and IP addressing remain unchanged.
- **Minimal Overhead:** The lightweight C++ implementation ensures fast packet processing and minimal latency.

## **Installation & Usage**
### **Building the Project**
EtherBridge requires a C++ compiler and standard networking libraries. To compile the server and client:

```sh
mkdir build && cd build
cmake ..
make
```

### **Running the Server on the Robot**
```sh
./etherbridge server --external-interface wlan0 --internal-interface eth0
```

The server will bind to the robot's Wi-Fi interface and listen on UDP port `5432`.

### **Running the Client on the Debugging Host**
```sh
sudo ./etherbridge client --peer <robot> --bridge <robot-internal-ip>
```

- Replace `<robot>` with an IP address or hostname of the robot.
- Replace `<robot-internal-ip>` with a static IP inside the robot's internal IP range.

After running the client, a new TAP device will be available on the host machine, allowing direct communication with the robot's internal network.

## **Example Use Cases**
- **Debugging & Monitoring:** Connect directly to the robot's sensors and actuators without physical access.
- **Remote Development:** Develop and test robot applications remotely without requiring direct Ethernet access.
- **Network Packet Analysis:** Monitor internal network traffic for debugging and security analysis.

## **License**
EtherBridge is released under the MIT License. Feel free to use, modify, and distribute it.
