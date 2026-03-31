from pcap_parser import parse_pcap

def main():

    # example usage
    filename = "data/example.pcap"
    df = parse_pcap(filename)
    print(df)


if __name__ == "__main__":
    main()
