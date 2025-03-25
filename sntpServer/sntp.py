import socket
import struct


def get_time(origin_time, false_in_seconds):
    changed_time =  origin_time + false_in_seconds * 10000000000
    return changed_time

def create_ntp_packet(origin_time, changed_time):
    packet = struct.pack(
        '!BBBBIIIQQQQ',
        0x1c, 1, 0, 0, 0, 0, 0, 0,
        origin_time, #из запроса клиента
        changed_time, #время получения запроса
        changed_time #время отправки ответа
    )
    return packet


def main():
    with open("seconds_config.txt", "r") as f:
        false_in_seconds = int(f.readline())
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 123))
    while True:
        try:
            data, address = server_socket.recvfrom(1024)
            origin_time = struct.unpack('!Q', data[40:48])[0]
            changed_time = get_time(origin_time, false_in_seconds)
            packet = create_ntp_packet(origin_time, changed_time)
            server_socket.sendto(packet, address)
        except Exception as e:
            print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()