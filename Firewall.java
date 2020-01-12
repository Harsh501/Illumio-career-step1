import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;



interface validate_data {
    boolean accept_packet(String direction, String protocol, int port, String ip_address);
}

class TrieNode {
    boolean isEnd;
    TrieNode[] children = new TrieNode[2];
    List<int[]> port_range;
    int value;

    public TrieNode() {

        isEnd = false;
        Arrays.fill(children , null);
        port_range = new ArrayList<>();
        value = Integer.MIN_VALUE;
    }

}

class Firewall implements validate_data {

    // Constructor in Class because Java does not support Constructors in Interface.
    private BufferedReader br = null;
    private TrieNode inbound_tcp = new TrieNode();
    private TrieNode outbound_tcp = new TrieNode();
    private TrieNode inbound_udp = new TrieNode();
    private TrieNode outbound_udp = new TrieNode();
    //Counter to count number of lines in the file.
    int count = 0;

    public Firewall(String path_to_file) {
        try {
            br = new BufferedReader(new FileReader(path_to_file));

            String newLine;
            while ((newLine = br.readLine()) != null) {
                preprocess_data(newLine.split(","));
                count++;
            }
            System.out.println(count + " number of lines");
            br.close();
            System.out.println("File read and parsed successfully");
        } catch (FileNotFoundException e) {
            System.out.println("The file does not exist at the specified path.");
        } catch (Exception e) {
            System.out.println("There are some issues with provided file, please check the file for its contents.");
            e.printStackTrace();
        }
    }

    /* Considering the content in the input file is valid */
    private void preprocess_data(String[] line) throws Exception {
        String direction = line[0];
        String protocol = line[1];
        String port = line[2];
        String ip_address = line[3];
        if (direction.equals("inbound")) {
            if (protocol.equals("tcp")) {

                getIPAndPortData(ip_address, port, inbound_tcp);

            } else if (protocol.equals("udp")) {

                getIPAndPortData(ip_address, port, inbound_udp);

            } else
                throw new Exception("protocol defined incorrectly");

        } else if (direction.equals("outbound")) {

            if (protocol.equals("tcp")) {

                getIPAndPortData(ip_address, port, outbound_tcp);

            } else if (protocol.equals("udp")) {

                getIPAndPortData(ip_address, port, outbound_udp);

            } else
                throw new Exception("protocol defined incorrectly");
        } else
            throw new Exception("Direction defined incorrectly");

    }

    private void getIPAndPortData(String ip_address, String port, TrieNode root) throws UnknownHostException {
        if (ip_address.contains("-")) {
            String[] ip_split = ip_address.split("-");
            int start = pack(InetAddress.getByName(ip_split[0]).getAddress());
            int end = pack(InetAddress.getByName(ip_split[1]).getAddress());

            while (start != end) {
                String IntToIp = InetAddress.getByAddress(unpack(start++)).getHostAddress();
                insertIntoTrie(root, IntToIp, port);
            }

        } else {
            insertIntoTrie(root, ip_address, port);
        }
    }

    private void insertIntoTrie(TrieNode root, String intToIp, String port) {

        String[] IDs = intToIp.split("\\.");
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < IDs.length; i++) {
            int current = Integer.parseInt(IDs[i]);
            String intToBinary = Integer.toBinaryString(current);
            sb.append(intToBinary);
        }

        TrieNode temp = root;
        int len = sb.length();
        for (int i = 0; i < len; i++) {

            int index = Character.getNumericValue(sb.charAt(i));
            if (temp.children[index] == null) {
                temp.children[index] = new TrieNode();
                temp.value = index;
            }
            temp = temp.children[index];

            if (i == len - 1) {
                temp.isEnd = true;
                if (temp.port_range == null || temp.port_range.size() == 0) {
                    temp.port_range = new ArrayList<>();
                }
            }
        }

        IntegratePorts(temp.port_range, port);
    }

    private void IntegratePorts(List<int[]> port_range, String port) {
        int lower = Integer.MIN_VALUE;
        int upper = Integer.MIN_VALUE;

        if (!port.contains("-")) {
            lower = Integer.parseInt(port);
            upper = Integer.parseInt(port);
        } else {
            String[] port_split = port.split("-");
            lower = Integer.parseInt(port_split[0]);
            upper = Integer.parseInt(port_split[1]);
        }

        int new_port_range[] = { lower, upper };
        if (port_range == null)
            return;
        if (port_range.size() == 0) {
            port_range.add(new_port_range);
            return;
        }
        if (port_range.contains(new_port_range)) {
            return;
        }

        int port_range_size = port_range.size();
        int overlap_idx = 0;
        for (int i = 0; i < port_range_size; i++) {

            int[] curr = port_range.get(i);
            int start = curr[0];
            int end = curr[1];

            if (i + 1 < port_range_size) {
                if (end >= lower - 1) {
                    if (upper + 1 < port_range.get(i + 1)[0]) {
                        port_range.get(i)[0] = Math.min(lower, start);
                        port_range.get(i)[1] = Math.max(upper, end);
                        return;
                    } else {
                        overlap_idx = i;
                        break;
                    }
                } else if (upper + 1 < port_range.get(i + 1)[0]) {
                    overlap_idx = i;
                    break;
                }
            } else if (lower - 1 <= end) {
                port_range.get(i)[0] = Math.min(lower, start);
                port_range.get(i)[1] = Math.max(end, upper);
                return;
            } else {
                overlap_idx = i;
            }

        }

        if (port_range.get(overlap_idx)[1] < lower - 1 && port_range.get(overlap_idx)[0] > upper + 1) {
            port_range.add(overlap_idx + 1, new_port_range);
        } else if (overlap_idx + 1 == port_range_size) {
            port_range.add(new_port_range);
        } else {

            port_range.get(overlap_idx)[0] = Math.min(lower,
                    Math.min(port_range.get(overlap_idx)[0], port_range.get(overlap_idx + 1)[0]));
            port_range.get(overlap_idx)[1] = Math.max(upper,
                    Math.max(port_range.get(overlap_idx)[1], port_range.get(overlap_idx + 1)[1]));
            port_range.remove(overlap_idx + 1);
        }

    }

    
    public boolean accept_packet(String direction, String protocol, int port, String ip_address) {

        if (direction.equals("inbound")) {
            if (protocol.equals("tcp")) {

                return CheckPacketInfo(inbound_tcp, port, ip_address);

            } else if (protocol.equals("udp")) {

                return CheckPacketInfo(inbound_udp, port, ip_address);

            } else
                return false;

        } else if (direction.equals("outbound")) {

            if (protocol.equals("tcp")) {

                return CheckPacketInfo(outbound_tcp, port, ip_address);

            } else if (protocol.equals("udp")) {

                return CheckPacketInfo(outbound_udp, port, ip_address);

            } else
                return false;
        }

        return false;

    }

    private  boolean CheckPacketInfo(TrieNode root, int port, String ip_address) {

        // Step 1:Search for IP

        TrieNode temp = root;
        String[] IDs = ip_address.split("\\.");
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < IDs.length; i++) {
            int current = Integer.parseInt(IDs[i]);
            String intToBinary = Integer.toBinaryString(current);
            sb.append(intToBinary);
        }

        for (int i = 0; i < sb.length(); i++) {
            int index = Character.getNumericValue(sb.charAt(i));
            if (temp.children[index] == null)
                return false;
            temp = temp.children[index];
        }
        if (temp.isEnd == false)
            return false;

        return checkForPort(temp, port);
    }

    private boolean checkForPort(TrieNode temp, int port) {

        if (temp == null)
            return false;
        List<int[]> ports = temp.port_range;
        int size = ports.size();
        for (int i = 0; i < size; i++) {
            int[] curr = ports.get(i);
            if (i + 1 < size && curr[1] < port && ports.get(i + 1)[0] > port) {
                return false;
            }
            if (curr[0] <= port && curr[1] >= port) {
                return true;
            }
        }
        return false;
    }

    //Function for Converting BinaryString to int.

    private int pack(byte[] bytes) {
        int val = 0;
        for (int i = 0; i < bytes.length; i++) {
            val <<= 8;
            val |= bytes[i] & 0xff;
        }
        return val;
    }

    //Function for Convert int ip to String.
    private byte[] unpack(int bytes) {
        return new byte[] { (byte) ((bytes >>> 24) & 0xff), (byte) ((bytes >>> 16) & 0xff),
                (byte) ((bytes >>> 8) & 0xff), (byte) ((bytes) & 0xff) };
    }

    public static void main(String args[]) throws Exception {

        long time_1 = System.currentTimeMillis();
        Firewall firewall = new Firewall("data.csv");
        long time_2 = System.currentTimeMillis();
        // System.out.println(time_2 - time_1 + "milliseconds");
        
        time_1 = System.currentTimeMillis();

        System.out.println(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
        System.out.println(firewall.accept_packet("inbound", "udp", 53, "192.168.2.1"));
        System.out.println(firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
        System.out.println(firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
        System.out.println(firewall.accept_packet("inbound", "udp", 24, "52.12.48.92"));
        System.out.println(firewall.accept_packet("inbound", "udp", 81, "52.12.48.92"));
        System.out.println(firewall.accept_packet("outbound", "udp", 121-909, "52.12.48.92"));
        System.out.println(firewall.accept_packet("outbound", "tcp", 181-222, "52.12.48.92-67.54.55.67"));
        System.out.println(firewall.accept_packet("inbound", "udp", 12234-19090, "90.12.87.22-91.22.234.1"));
        System.out.println(firewall.accept_packet("outbound", "tcp", 90-109, "72.52.34.23"));
        System.out.println(firewall.accept_packet("inbound", "udp", 19, "152.87.68.221-181.90.222.32"));

        time_2 = System.currentTimeMillis();
        // System.out.println(time_2 - time_1 + "milliseconds");
    }

  
}