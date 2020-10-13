import psutil

if __name__ == "__main__":
    cpu = psutil.disk_usage('/')

    print(cpu)
    print(type(cpu))

    networks = psutil.net_io_counters(pernic=True)
    # print(networks)
    # print(type(networks))
    for interfaces, messages in networks.items():
        print(interfaces+': '+str(messages))