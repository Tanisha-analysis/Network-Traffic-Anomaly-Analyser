# Network Traffic Anomaly Analyser
## Project Overview
The Network Traffic Anomaly Analyser is a mini project developed using C++. It analyses network traffic data stored in a CSV file and identifies unusual traffic patterns based on predefined rules.

The project is designed for offline analysis and does not require a database, internet connection, or live packet capture.

## Objectives
- Analyse network traffic records from a CSV file.
- Identify unusually large packets.
- Detect high traffic frequency from a single source IP address.
- Analyse protocol distribution.
- Generate alerts and a traffic analysis report.

## Technologies Used
- **Programming Language:** C++
- **Data Format:** CSV
- **Compiler:** GCC/G++
- **Development Environment:** Visual Studio Code

## Anomaly Detection Rules
1. **Large Packet Detection:** Flags packets larger than 1500 bytes.
2. **High Traffic Frequency:** Flags more than 100 records from the same source IP within a 10-second window.
3. **Protocol Distribution:** Flags a protocol when it accounts for more than 80% of the records.

## How to Compile and Run
1. Install a C++ compiler such as GCC.
2. Open the project folder in a terminal.
3. Compile the source code:

   ```bash
   g++ newain.cpp -o analyser
   ```

4. Run the program on Windows:

   ```powershell
   .\analyser.exe
   ```

5. Keep `network_traffic.csv` in the location expected by the program.

## Limitations
This project uses predefined rules to identify unusual patterns. It analyses existing CSV data and does not capture live network traffic. Its alerts indicate potentially unusual activity and do not, by themselves, prove a cyberattack.

## Author
Developed as an MCA mini project.

## Project Files

- [C++ Source Code (newain.cpp)](./newain.cpp)
- [Network Traffic Dataset (network_traffic.csv)](./network_traffic.csv)

