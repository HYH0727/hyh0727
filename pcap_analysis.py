import struct, requests, socket
from datetime import datetime

# pcap 파일을 읽는다
fd = open("C:\\Users\\r2com\\desktop\\네트워크 시스템 강의\\ddos_pcap\\1.pcap", "rb")
# data 변수에 pcap 파일의 전체를 복사
data = fd.read()
# pcap 파일의 핸들을 닫는다
fd.close()
# 파일을 분석 시 
offset = 0
# global header 를 읽는다. 실제 
global_header = data[0:24]
offset += 24
number = 1
# 파일 끝가지 동작하기 위해 무한반복문 시작

mac_dict = {
    
}
while True:
    # 패킷 헤더를 16바이트 읽는다
    packet_header = data[offset : offset + 16]
    offset += 16
    # 시간을 구한다
    # ts_sec 는 유닉스타임스탬프의 초단위
    # ts_usec 는 유닉스타임스탬프의 밀리세컨드 단위
    ts_sec = struct.unpack("<L", packet_header[0:4])[0]
    ts_usec = struct.unpack("<L", packet_header[4:8])[0]
    # 따라서 유닉스타임스탬프 형식으로 시간(초 + 밀리세컨드)을 변환
    packet_datetime = datetime.fromtimestamp(float(str(ts_sec) + "." + str(ts_usec)))
    # 가변길의 패킷길이를 구함
    packet_length = struct.unpack("<L", packet_header[8:12])[0]
    print(number, packet_datetime, packet_length)
    
    # packet frame 변수에 1계층 전기적 analog 신호를 digital 신호로 변환하여 저장
    packet_offset = 0
    packet_frame = data[offset : offset + packet_length]
    ethernet_frame = packet_frame[packet_offset : packet_offset + 14]
    dmac = ethernet_frame[packet_offset: packet_offset+6].hex()
    smac = ethernet_frame[packet_offset + 6: packet_offset+12].hex()
    ethernet_type = ethernet_frame[12:14].hex()
    #ethernet_type = struct.unpack("<H", ethernet_frame[12:14])[0]
    print(dmac, smac, ethernet_type)
    '''
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Referer" : "https://macvendors.com/"
    }
    if dmac not in mac_dict:        
        response = requests.get("https://macvendors.com/query/" + dmac, headers=headers)
        print(response.status_code, response.content)
        mac_dict[dmac] = response.content
    else:
        print(222, mac_dict[dmac])
    if smac not in mac_dict:
        response = requests.get("https://macvendors.com/query/" + smac, headers=headers)
        print(response.status_code, response.content)
        mac_dict[smac] = response.content
    else:
        print(111, mac_dict[smac])
    '''
    packet_offset += 14
    ip_header = packet_frame[packet_offset:]
    if ethernet_type == "0800":
        ttl = struct.unpack("<B", ip_header[8:9])[0]
        protocol_type = struct.unpack("<B", ip_header[9:10])[0]
        sip = socket.inet_ntoa(ip_header[12:16])
        dip = socket.inet_ntoa(ip_header[16:20])
        print(ttl, sip, dip, protocol_type)
        
    
    
    # 2계층
    # 3계층
    # 4계층
    # 7계층
    
    
    offset += packet_length
    number += 1
    if number > 100:
        break
    # 파일의 길이보다 offset이 크거가 같다면 무한반복문 종료
    if offset >= len(data):
        break









