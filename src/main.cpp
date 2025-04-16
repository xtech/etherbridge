//
// Created by clemens on 19.02.25.
//
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <spdlog/spdlog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <CLI11.hpp>
#include <fcntl.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <thread>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

constexpr uint16_t BIND_PORT = 5432;

inline std::string IpIntToString(const uint32_t ip) {
    in_addr addr{.s_addr = ntohl(ip)};
    const char *addrStr = inet_ntoa(addr);
    return addrStr;
}

static std::atomic_bool should_stop{false};

void signal_handler(int) {
    spdlog::info("Stopping!");
    should_stop.exchange(true);
}

/**
 * Create a RAW socket on the given interface
 * @param interface name of the interface to use
 * @param mac_address return value for the mac address (can be used for filtering)
 * @return the socket fd, -1 on error
 */
int SetupRawSocket(const std::string &interface, uint8_t *mac_address) {
    // Find the index of the interface
    unsigned int idx = if_nametoindex(interface.c_str());
    if (idx == 0) {
        spdlog::error("Error getting index for interface {}: {}", interface, strerror(errno));
        return -1;
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sockfd < 0) {
        spdlog::error("Error creating raw socket: {}", strerror(errno));
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;      // 1 second
    timeout.tv_usec = 0;     // 0 microseconds

    // Set receive timeout
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        return -1;
    }

    // Bind raw socket to the internal interface via index (via name not possible with AF_PACKET)
    sockaddr_ll saddr{};
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = idx;
    if (bind(sockfd, reinterpret_cast<sockaddr *>(&saddr), sizeof(saddr)) < 0) {
        spdlog::error("Error binding raw socket: {}", strerror(errno));
        return -1;
    }

    // Enable promiscuous mode - for performance we should sniff the tap device and use the unicast instead
    struct packet_mreq mreq{};
    mreq.mr_ifindex = idx;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        spdlog::error("Error enabling promiscuous mode: {}", strerror(errno));
        return -1;
    }

    struct ifreq ifr{};
    strcpy(ifr.ifr_name, interface.c_str());
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr, sizeof(ifr)) < 0) {
        spdlog::error("Error fetching mac for interface: {}", strerror(errno));
        return -1;
    }

    spdlog::info("Interface MAC: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}", ifr.ifr_ifru.ifru_hwaddr.sa_data[0],
                 ifr.ifr_ifru.ifru_hwaddr.sa_data[1], ifr.ifr_ifru.ifru_hwaddr.sa_data[2],
                 ifr.ifr_ifru.ifru_hwaddr.sa_data[3], ifr.ifr_ifru.ifru_hwaddr.sa_data[4],
                 ifr.ifr_ifru.ifru_hwaddr.sa_data[5]);
    memcpy(mac_address, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

    return sockfd;
}

/**
 * Get the IP address for a given interface name
 * @param interface_name Name of the interface
 * @param netmask return value for the netmask
 * @return the interface's IP address as int. 0 on error.
 */
uint32_t GetIPFromInterfaceName(const std::string &interface_name, uint32_t *netmask) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name, interface_name.c_str());
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return 0;
    }

    uint32_t ip = ntohl(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr);
    spdlog::debug("Resolved address {} for interface {}", IpIntToString(ip), interface_name);

    // Fetch netmask
    if (netmask != nullptr) {
        if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
            spdlog::error("Error resolving netmask for {}: ", interface_name, strerror(errno));
            close(fd);
            return 0;
        }
        *netmask = ntohl(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr);
        spdlog::debug("Resolved netmask {} for interface {}", IpIntToString(*netmask), interface_name);
    }

    close(fd);

    return ip;
}

/**
 * Creates UDP socket bound to specified IP and port
 * @param bind_ip Binds to this IP (0.0.0.0 for any)
 * @param bind_port Binds to this port (0 for random)
 * @return fd, -1 on error
 */
int GetUDPSocket(uint32_t bind_ip, uint16_t bind_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    struct timeval timeout;
    timeout.tv_sec = 1;      // 1 second
    timeout.tv_usec = 0;     // 0 microseconds

    // Set receive timeout
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        return -1;
    }

    // Bind Socket
    sockaddr_in saddr{};
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(bind_ip);
    saddr.sin_port = htons(bind_port);
    if (bind(fd, reinterpret_cast<sockaddr *>(&saddr), sizeof(saddr)) < 0) {
        close(fd);
        spdlog::error("Error on bind: {}", strerror(errno));
        return -1;
    }
    return fd;
}

struct ServerConfig {
    std::string external_interface;
    std::string internal_interface;
};


struct ClientConfig {
    std::string peer_ip;
    std::string bridge_ip;
};

struct CopyThreadArg {
    std::string name;
    // FD to read from
    int fd1;
    bool fd1_is_socket;
    // FD to send to
    int fd2;
    bool fd2_is_socket;
    // Runs as long as this is false
    std::atomic_bool &should_stop;
    // Mutex to read/write peer info
    std::mutex *state_mutex;
    uint32_t *peer_ip;
    uint16_t *peer_port;
    // Either we set the peer info or read the peer info
    bool provide_peer_info;
    size_t *bytes_read;
    size_t *packets_read;
};

/**
 * Copies data from fd1 -> fd2
 * @param args A CopyThreadArg Struct
 */
void CopyThread(void *args) {
    const auto thread_args = static_cast<const CopyThreadArg *>(args);

    if (thread_args->state_mutex == nullptr && !thread_args->provide_peer_info) {
        spdlog::error("MutexPtr was null, but we need the peer info. Exiting.");
        return;
    }

    uint8_t buffer[2048];
    sockaddr_in addr{};
    ssize_t received;
    while (!thread_args->should_stop.load()) {
        if (thread_args->fd1_is_socket) {
            if (thread_args->provide_peer_info) {
                socklen_t sender_len = sizeof(addr);
                received = recvfrom(thread_args->fd1,
                                    buffer, sizeof(buffer), 0,
                                    reinterpret_cast<sockaddr *>(&addr), &sender_len);
            } else {
                received = recv(thread_args->fd1, buffer, sizeof(buffer), 0);
            }
            if (received < 0) {
                if (errno != EAGAIN) {
                    spdlog::warn("Error during recvfrom: {} [{}]", strerror(errno), thread_args->name);
                }
                continue;
            }
        } else {
            // fd1 is fd
            fd_set fds;
            struct timeval timeout;

            FD_ZERO(&fds);
            FD_SET(thread_args->fd1, &fds);

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int ret = select(thread_args->fd1 + 1, &fds, NULL, NULL, &timeout);
            if (ret == 0) {
                received = 0;
            } else if (ret > 0) {
                // fd is ready
                received = read(thread_args->fd1, buffer, sizeof(buffer));
            } else {
                // Error, pass it on
                received = ret;
            }
        }
        if (received == 0) {
            // timeout
            continue;
        }

        if (received > 0) {
            if (thread_args->state_mutex != nullptr) {
                thread_args->state_mutex->lock();
                *thread_args->bytes_read += received;
                *thread_args->packets_read += 1;
                thread_args->state_mutex->unlock();
            }
            if (thread_args->state_mutex != nullptr && thread_args->provide_peer_info) {
                thread_args->state_mutex->lock();
                if ((*thread_args->peer_ip != addr.sin_addr.s_addr || *thread_args->peer_port != addr.
                     sin_port) && addr.sin_addr.s_addr && addr.sin_port) {
                    *thread_args->peer_ip = addr.sin_addr.s_addr;
                    *thread_args->peer_port = addr.sin_port;
                    spdlog::info("Updating Peer {}:{}", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                     }
                thread_args->state_mutex->unlock();
            }

            // Got a packet, redirect it to the raw socket
            spdlog::debug("{} read packet (size = {})!", thread_args->name, received);
            if (thread_args->fd2_is_socket) {
                if (thread_args->provide_peer_info) {
                    // fd2 is the raw socket, so no peer info needed
                    send(thread_args->fd2, buffer, received, 0);
                } else {
                    // use the peer info as receiver for tunneling
                    addr.sin_family = AF_INET;
                    thread_args->state_mutex->lock();
                    addr.sin_addr.s_addr = *thread_args->peer_ip;
                    addr.sin_port = *thread_args->peer_port;
                    thread_args->state_mutex->unlock();
                    sendto(thread_args->fd2, buffer, received, 0, reinterpret_cast<const struct sockaddr *>(&addr),
                           sizeof(addr));
                }
            } else {
                // fd2 is a file
                write(thread_args->fd2, buffer, received);
            }
        }
    }
}

int CreateTapDevice(const std::string &ip_to_use, const std::string &netmask) {
    struct ifreq ifr{};
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        spdlog::error("Opening /dev/net/tun: {}", strerror(errno));
        return -1;
    }

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI; // TAP device without packet info

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        spdlog::error("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }


    int config_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (config_sockfd < 0) {
        spdlog::error("socket()");
        close(fd);
        return -1;
    }


    // Set the IP address and netmask, then set the device as up
    struct sockaddr_in sin{};
    sin.sin_addr.s_addr = inet_addr(ip_to_use.c_str());
    sin.sin_family = AF_INET;
    ifr.ifr_ifru.ifru_addr.sa_family = AF_INET;
    memcpy(&ifr.ifr_ifru.ifru_addr, &sin, sizeof(sin));
    if (ioctl(config_sockfd, SIOCSIFADDR, &ifr) < 0) {
        spdlog::error("error SIOCSIFADDR");
        close(config_sockfd);
        close(fd);
        return -1;
    }

    sin.sin_addr.s_addr = inet_addr(netmask.c_str());
    memcpy(&ifr.ifr_netmask, &sin, sizeof(sin));
    if (ioctl(config_sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        spdlog::error("error SIOCSIFNETMASK");
        close(config_sockfd);
        close(fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(config_sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        spdlog::error("ioctl(SIOCSIFFLAGS)");
        close(config_sockfd);
        close(fd);
        exit(1);
    }

    close(config_sockfd);

    return fd;
}

int StartServer(const ServerConfig &config) {
    // Fetch the IP address for the external interface (so that we can bind to that one specifically)
    uint32_t external_netmask;
    uint32_t external_ip = GetIPFromInterfaceName(config.external_interface, &external_netmask);

    if (external_ip == 0) {
        spdlog::error(
            "Error resolving IP addresses on {}. Make sure the interfaces are correct and have an IPv4 address assigned.",
            config.external_interface);
        return -1;
    }

    spdlog::info("Running in server mode {} <--> {} ({}:{})", config.internal_interface,
                 config.external_interface, IpIntToString(external_ip), BIND_PORT);

    uint8_t mac_address[6];
    int raw_sockfd = SetupRawSocket(config.internal_interface, mac_address);
    if (raw_sockfd < 0) {
        return -2;
    }

    // Create the UDP socket
    int ext_socket_fd = GetUDPSocket(external_ip, BIND_PORT);

    if (ext_socket_fd < 0) {
        spdlog::error("Error starting external UDP socket");
        return -3;
    }

    std::mutex state_mutex{};
    uint32_t peer_ip = 0;
    uint16_t peer_port = 0;

    size_t udp_bytes_read = 0;
    size_t udp_packets_read = 0;
    size_t raw_bytes_read = 0;
    size_t raw_packets_read = 0;
    CopyThreadArg udpToRaw{
        .name = "udpToRaw",
        .fd1 = ext_socket_fd,
        .fd1_is_socket = true,
        .fd2 = raw_sockfd,
        .fd2_is_socket = true,
        .should_stop = should_stop,
        .state_mutex = &state_mutex,
        .peer_ip = &peer_ip,
        .peer_port = &peer_port,
        .provide_peer_info = true,
        .bytes_read = &udp_bytes_read,
        .packets_read = &udp_packets_read
    };


    // Start thread copying from UDP socket to the RAW socket
    std::thread udpToRawThread{CopyThread, &udpToRaw};

    std::thread statPrinter{
        [&] {
            while (!should_stop.load()) {
                state_mutex.lock();
                spdlog::info("Data Transferred: ({} pkts / {} bytes) <--> ({} pkts / {} bytes)", raw_packets_read,
                             raw_bytes_read, udp_packets_read, udp_bytes_read);
                raw_packets_read = raw_bytes_read = udp_packets_read = udp_bytes_read = 0;
                state_mutex.unlock();
                for (int i = 0; i < 1000 && !should_stop.load(); i++) {
                    usleep(10000);
                }
            }
        }
    };

    uint8_t buffer[2048];
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    while (!should_stop.load()) {
        ssize_t received = recv(raw_sockfd, buffer, sizeof(buffer), 0);
        if (received == -1) {
            spdlog::warn("Error reading RAW socket: {}", strerror(errno));
            continue;
        }

        if (received < sizeof(struct ether_header)) {
            spdlog::warn("Got packet smaller than the ethernet header!");
            continue;
        }
        const auto header = reinterpret_cast<struct ether_header *>(buffer);

        // Redirect if broadcast or doesn't match the physical interface we're using
        if ((header->ether_dhost[0] & 0b1) != 0 || (memcmp(header->ether_dhost, mac_address, 6) != 0 && memcmp(
                                                        header->ether_shost, mac_address, 6) != 0)) {
            spdlog::debug("Received packet. size={}", received);

            state_mutex.lock();
            raw_bytes_read += received;
            raw_packets_read++;
            addr.sin_port = peer_port;
            addr.sin_addr.s_addr = peer_ip;
            state_mutex.unlock();
            if (addr.sin_port > 0 && addr.sin_addr.s_addr > 0) {
                sendto(ext_socket_fd, buffer, received, 0, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
            }
        }
    }

    udpToRawThread.join();
    statPrinter.join();

    return 0;
}

int StartClient(const ClientConfig &config) {
    spdlog::info("Running in client mode {} <--> {}:{}", config.bridge_ip,
                 config.peer_ip, BIND_PORT);


    int tap_fd = CreateTapDevice(config.bridge_ip, "255.255.255.0");

    // Resolve the remote peer
    addrinfo *addrinfo = nullptr;
    if (getaddrinfo(config.peer_ip.c_str(), nullptr, nullptr, &addrinfo) < 0) {
        spdlog::error("Could not resolve {}", config.peer_ip);
        return -1;
    }

    int udp_socket_fd = GetUDPSocket(0,0);

    if (udp_socket_fd < 0) {
        spdlog::error("Error creating UDP socket");
        return -1;
    }

    std::mutex state_mutex{};
    uint32_t peer_ip = reinterpret_cast<const sockaddr_in*>(addrinfo->ai_addr)->sin_addr.s_addr;
    uint16_t peer_port = htons(BIND_PORT);

    size_t udp_bytes_read = 0;
    size_t udp_packets_read = 0;
    size_t raw_bytes_read = 0;
    size_t raw_packets_read = 0;
    CopyThreadArg tapToUdp{
        .name = "tapToUdp",
        .fd1 = tap_fd,
        .fd1_is_socket = false,
        .fd2 = udp_socket_fd,
        .fd2_is_socket = true,
        .should_stop = should_stop,
        .state_mutex = &state_mutex,
        .peer_ip = &peer_ip,
        .peer_port = &peer_port,
        .provide_peer_info = false,
        .bytes_read = &raw_bytes_read,
        .packets_read = &raw_packets_read
    };
    CopyThreadArg udpToTap{
        .name = "udpToTap",
        .fd1 = udp_socket_fd,
        .fd1_is_socket = true,
        .fd2 = tap_fd,
        .fd2_is_socket = false,
        .should_stop = should_stop,
        .state_mutex = &state_mutex,
        .peer_ip = &peer_ip,
        .peer_port = &peer_port,
        .provide_peer_info = false,
        .bytes_read = &udp_bytes_read,
        .packets_read = &udp_packets_read
    };


    // Start thread copying from UDP socket to the RAW socket
    std::thread udpToTapThread{CopyThread, &udpToTap};
    std::thread tapToUdpThread{CopyThread, &tapToUdp};

    std::thread statPrinter{
        [&] {
            while (!should_stop.load()) {
                state_mutex.lock();
                spdlog::info("Data Transferred: ({} pkts / {} bytes) <--> ({} pkts / {} bytes)", raw_packets_read,
                             raw_bytes_read, udp_packets_read, udp_bytes_read);
                raw_packets_read = raw_bytes_read = udp_packets_read = udp_bytes_read = 0;
                state_mutex.unlock();
                for (int i = 0; i < 10 && !should_stop.load(); i++) {
                    usleep(1000000);
                }
            }
        }
    };


    udpToTapThread.join();
    tapToUdpThread.join();
    statPrinter.join();
    return 0;
}

int main(int argc, char **argv) {
    spdlog::set_level(spdlog::level::info);
    CLI::App app{"etherbridge helps tapping into networks for debugging"};
    argv = app.ensure_utf8(argv);

    // Exactly one subcommand
    app.require_subcommand(1);

    const auto server_subcommand = app.add_subcommand("server");
    ServerConfig server_config{};
    server_subcommand->add_option("--external-interface,-e", server_config.external_interface,
                                  "The external interface to use (e.g. wlan0)")->required();
    server_subcommand->add_option("--internal-interface,-i", server_config.internal_interface,
                                  "The external interface to use (e.g. eth0)")->required();


    const auto client_subcommand = app.add_subcommand("client");
    ClientConfig client_config{};
    client_subcommand->add_option("--peer", client_config.peer_ip, "The peer to use");
    client_subcommand->add_option("--bridge", client_config.bridge_ip, "The IP to use for the bridge");


    CLI11_PARSE(app, argc, argv);

    signal(SIGINT, signal_handler);

    if (server_subcommand->parsed()) {
        return -StartServer(server_config);
    } else if (client_subcommand->parsed()) {
        return -StartClient(client_config);
    }
}
