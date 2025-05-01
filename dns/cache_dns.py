import socket
import threading
import time
import pickle
import os
import struct
from io import BytesIO
from collections import defaultdict
from typing import List, Tuple, Optional, Any

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53
UPSTREAM_RESOLVER = "8.8.8.8"
UPSTREAM_PORT = 53
CACHE_FILE = "dns_cache_custom_parser.pkl"

cache = defaultdict(list)
cache_lock = threading.Lock()
running = True

RECORD_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 28: 'AAAA'}
RECORD_TYPES_TO_INT = {'A': 1, 'NS': 2, 'CNAME': 5, 'PTR': 12, 'AAAA': 28}

def get_str_type(ans_type):
    return RECORD_TYPES.get(ans_type, f'TYPE{ans_type}')

def get_int_type(ans_type):
    return RECORD_TYPES_TO_INT.get(ans_type.upper(), None)


class Header:
    def __init__(self, data):
        self._raw_data = data.read(12)

        if len(self._raw_data) < 12:
            raise ValueError("Insufficient data for DNS Header")

        (self.id, self.flags, self.qdcount, self.ancount, self.nscount,
         self.arcount) = struct.unpack('!HHHHHH', self._raw_data)

        self.qr = (self.flags >> 15) & 0x1
        self.opcode = (self.flags >> 11) & 0xF
        self.aa = (self.flags >> 10) & 0x1
        self.tc = (self.flags >> 9) & 0x1
        self.rd = (self.flags >> 8) & 0x1
        self.ra = (self.flags >> 7) & 0x1
        self.z = (self.flags >> 4) & 0x7
        self.rcode = self.flags & 0xF

    def build_response_header(self, ancount: int, nscount: int, arcount: int, rcode: int) -> bytes:
        """Собирает заголовок ответа."""
        new_flags = (1 << 15) | (self.opcode << 11) | (self.rd << 8) | (1 << 7) | rcode
        return struct.pack('!HHHHHH', self.id, new_flags, self.qdcount, ancount, nscount, arcount)

    def __bytes__(self) -> bytes:
        return self._raw_data

class Name:
    def __init__(self, bytestream: Optional[BytesIO] = None, all_data: bytes = b'',
                 name: Optional[str] = None):
        if bytestream is not None:
            self.all_data = all_data
            self._bytestream = bytestream
            try:
                 self.value, _ = self._parse(self._bytestream, self.all_data, 0)
                 if self.value is None:
                      raise ValueError("Failed to parse name due to error")
            except ValueError as e:
                 self.value = "[Name Parse Error]"
        elif name is not None:
            self.value = name.lower().rstrip('.')
            if not self.value:
                self.value = "."
        else:
            raise ValueError("Either bytestream or name must be provided")

    def _parse(self, data: BytesIO, all_data: bytes, depth: int) -> Tuple[Optional[str], int]:
        """Парсит имя, возвращает (имя, количество_прочитанных_байт_из_data)."""
        if depth > 10:
             raise ValueError("Max recursion depth reached")

        labels = []
        bytes_read_count = 0

        while True:
            length_byte = data.read(1)
            if not length_byte:
                raise ValueError("Unexpected end of stream while reading name length")
            length = length_byte[0]
            bytes_read_count += 1

            if length == 0:
                break
            elif (length & 0xC0) == 0xC0:
                second_byte = data.read(1)
                if not second_byte:
                    raise ValueError("Unexpected end of stream while reading name pointer offset")
                bytes_read_count += 1
                offset = ((length & 0x3F) << 8) + second_byte[0]

                if offset >= len(all_data):
                     raise ValueError(f"Invalid pointer offset {offset} (data length {len(all_data)})")

                pointer_stream = BytesIO(all_data[offset:])
                pointed_name, _ = self._parse(pointer_stream, all_data, depth + 1)
                if pointed_name is None:
                     raise ValueError(f"Failed to parse name at pointer offset {offset}")
                labels.append(pointed_name)
                break
            elif (length & 0xC0) == 0x00:
                if length > 63:
                     raise ValueError(f"Invalid label length {length} (>63)")
                label_bytes = data.read(length)
                if len(label_bytes) < length:
                     raise ValueError("Unexpected end of stream while reading label")
                bytes_read_count += length
                try:
                    label = label_bytes.decode('idna')
                except UnicodeDecodeError:
                    try:
                        label = label_bytes.decode('ascii')
                    except UnicodeDecodeError:
                         try:
                             label = label_bytes.decode('latin-1')
                         except UnicodeDecodeError:
                              raise ValueError("Cannot decode label bytes")
                labels.append(label)
            else:
                raise ValueError(f"Invalid label type/length byte: {length:#04x}")
        if not labels:
            full_name = "."
        else:
            if '.' in labels[-1]:
                 full_name = ".".join(labels[:-1] + [labels[-1].rstrip('.')])
            else:
                 full_name = ".".join(labels)
        full_name = full_name.strip('.').lower()
        if not full_name:
             full_name = "."

        return full_name, bytes_read_count


    def __bytes__(self) -> bytes:
        """Кодирует имя БЕЗ СЖАТИЯ."""
        if self.value == ".":
            return b'\x00'
        result = bytearray()
        for fragment in self.value.rstrip('.').split('.'):
            if not fragment: continue
            encoded_fragment = fragment.encode('idna')
            frag_len = len(encoded_fragment)
            if frag_len > 63:
                raise ValueError(f"Label '{fragment}' too long ({frag_len} > 63 bytes)")
            result.append(frag_len)
            result.extend(encoded_fragment)
        result.append(0)
        return bytes(result)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"Name('{self.value}')"

    def __eq__(self, other):
        if isinstance(other, Name):
            return self.value.rstrip('.') == other.value.rstrip('.')
        elif isinstance(other, str):
             return self.value.rstrip('.') == other.lower().rstrip('.')
        return False

    def __hash__(self):
         return hash(self.value.rstrip('.'))


class Question:
    def __init__(self, bytestream: BytesIO, all_data: bytes):
        self.name = Name(bytestream, all_data)
        q_data = bytestream.read(4)
        if len(q_data) < 4:
            raise ValueError("Insufficient data for Question Type/Class")
        self.q_type, self.q_class = struct.unpack('!HH', q_data)

    def __bytes__(self) -> bytes:
        return bytes(self.name) + struct.pack('!HH', self.q_type, self.q_class)

    def __repr__(self) -> str:
        return f"Question(name={self.name.value}, type={self.q_type}, class={self.q_class})"

class Record:
    def __init__(self, bytestream: BytesIO, all_data: bytes):
        self._all_data = all_data
        self.name = Name(bytestream, all_data)
        rr_header_data = bytestream.read(10)
        if len(rr_header_data) < 10:
            raise ValueError(f"Insufficient data for RR header for name {self.name.value}")

        (self.ans_type_int, self.ans_class, self.ttl,
         self.rec_len) = struct.unpack('!HHIH', rr_header_data)
        self.ans_type_str = get_str_type(self.ans_type_int)

        self.rdata_bytes = bytestream.read(self.rec_len)
        if len(self.rdata_bytes) < self.rec_len:
             raise ValueError(f"Insufficient RDATA for RR {self.name.value} {self.ans_type_str} (expected {self.rec_len}, got {len(self.rdata_bytes)})")

        self.rec_data = self._parse_rdata(self.ans_type_int, self.rdata_bytes, self._all_data)

    def _parse_rdata(self, rtype: int, rdata_bytes: bytes, all_data: bytes) -> Optional[Any]:
        """Парсит RDATA в зависимости от типа. Возвращает строку или None."""
        try:
            if rtype == 1: # A
                if len(rdata_bytes) == 4:
                    return socket.inet_ntop(socket.AF_INET, rdata_bytes)
                else: raise ValueError(f"Invalid length for A record: {len(rdata_bytes)}")
            elif rtype == 28: # AAAA
                if len(rdata_bytes) == 16:
                    return socket.inet_ntop(socket.AF_INET6, rdata_bytes)
                else: raise ValueError(f"Invalid length for AAAA record: {len(rdata_bytes)}")
            elif rtype in (2, 5, 12):
                rdata_stream = BytesIO(rdata_bytes)
                name_obj = Name(rdata_stream, all_data)
                if name_obj.value == "[Name Parse Error]":
                     raise ValueError("Failed to parse name within RDATA")
                return name_obj.value
            else:
                return None
        except (ValueError, OSError, UnicodeError, struct.error) as e:
             print(f"Warning: Failed to parse RDATA for {self.name.value} TYPE {rtype}: {e}")
             return None

    def __bytes__(self) -> bytes:
        """Собирает RR в байты. Возвращает bytes или None при ошибке."""
        if self.rec_data is None:
             print(f"Warning: Cannot build RR for {self.name.value} TYPE {self.ans_type_int} due to missing RDATA.")
             return b''

        try:
            if self.ans_type_int == 1: # A
                encoded_rdata = socket.inet_pton(socket.AF_INET, self.rec_data)
            elif self.ans_type_int == 28: # AAAA
                encoded_rdata = socket.inet_pton(socket.AF_INET6, self.rec_data)
            elif self.ans_type_int in (2, 5, 12): # NS, CNAME, PTR
                encoded_rdata = bytes(Name(name=self.rec_data))
            else:
                print(f"Warning: Cannot encode unsupported RR type {self.ans_type_int} for {self.name.value}")
                return b''

            if encoded_rdata is None:
                 raise ValueError("RDATA encoding failed")

            result = bytearray()
            result.extend(bytes(self.name))
            result.extend(struct.pack('!HHIH', self.ans_type_int, self.ans_class, self.ttl, len(encoded_rdata)))
            result.extend(encoded_rdata)
            return bytes(result)

        except (ValueError, OSError, struct.error) as e:
            print(f"Error building RR for {self.name.value} TYPE {self.ans_type_int} DATA '{self.rec_data}': {e}")
            return b''

    def __repr__(self) -> str:
         return f"Record(name={self.name.value}, type={self.ans_type_str}, ttl={self.ttl}, data={self.rec_data})"


class Packet:
    def __init__(self, data: bytes):
        self._raw_data = data
        self._bytestream = BytesIO(data)
        try:
            self.header = Header(self._bytestream)
            self.questions = self._parse_questions(self.header.qdcount)
            self.ans_records = self._parse_records(self.header.ancount)
            self.auth_records = self._parse_records(self.header.nscount)
            self.add_records = self._parse_records(self.header.arcount)
            self.parse_error = False
        except (ValueError, struct.error, IndexError) as e:
             print(f"Error parsing DNS packet: {e}")
             self.parse_error = True
             self.header = None
             self.questions = []
             self.ans_records = []
             self.auth_records = []
             self.add_records = []


    def _parse_questions(self, count: int) -> list[Question]:
        questions = []
        for _ in range(count):
             questions.append(Question(self._bytestream, self._raw_data))
        return questions

    def _parse_records(self, count: int) -> list[Record]:
        records = []
        for _ in range(count):
             records.append(Record(self._bytestream, self._raw_data))
        return records

    def build_response_packet(self, answers: List[Record], authority: List[Record] = [], additional: List[Record] = [], rcode: int = 0) -> bytes:
        """Собирает байты ответного пакета."""
        if self.header is None or not self.questions:
             print("Error: Cannot build response without original header/question.")
             return b''

        resp_header_bytes = self.header.build_response_header(
            ancount=len(answers),
            nscount=len(authority),
            arcount=len(additional),
            rcode=rcode
        )

        result = bytearray(resp_header_bytes)
        for q in self.questions:
            result.extend(bytes(q))
        for rec in answers:
            result.extend(bytes(rec))
        for rec in authority:
            result.extend(bytes(rec))
        for rec in additional:
            result.extend(bytes(rec))

        return bytes(result)

    def __bytes__(self) -> bytes:
        """Пересобирает пакет из его компонентов (если нужно)."""
        if self.header is None or self.parse_error:
             return self._raw_data
        result = bytearray(bytes(self.header))
        for q in self.questions:
            result.extend(bytes(q))
        for rec in self.ans_records:
            result.extend(bytes(rec))
        for rec in self.auth_records:
            result.extend(bytes(rec))
        for rec in self.add_records:
            result.extend(bytes(rec))
        return bytes(result)

# --- Функции кэша ---

def normalize_name_str(name: str) -> str:
    """Приводит строку имени к стандартному виду."""
    if name == ".":
        return "."
    return name.lower().rstrip('.') + '.'

def load_cache():
    global cache
    if not os.path.exists(CACHE_FILE):
        print(f"Файл кэша '{CACHE_FILE}' не найден. Запуск с пустым кэшем.")
        return
    print(f"Загрузка кэша из '{CACHE_FILE}'...")
    try:
        with open(CACHE_FILE, "rb") as f:
            loaded_data = pickle.load(f)
        if not isinstance(loaded_data, dict):
             print(f"Ошибка: Файл кэша '{CACHE_FILE}' имеет неверный формат.")
             cache = defaultdict(list)
             return

        current_time = time.time()
        valid_cache = defaultdict(list)
        expired_count = 0
        total_count = 0
        for key, entries in loaded_data.items():
             if not (isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], str) and isinstance(key[1], int)):
                 print(f"Предупреждение: Пропуск некорректного ключа в кэше: {key}")
                 continue
             valid_entries = []
             for entry in entries:
                 total_count += 1
                 if isinstance(entry, tuple) and len(entry) == 2 and isinstance(entry[1], (int, float)):
                      data, expires_at = entry
                      if expires_at > current_time:
                         valid_entries.append((data, expires_at))
                      else:
                         expired_count += 1
                 else:
                      print(f"Предупреждение: Пропуск некорректной записи в кэше для ключа {key}: {entry}")
             if valid_entries:
                 valid_cache[key] = valid_entries
        with cache_lock:
             cache = valid_cache
        print(f"Кэш загружен. Всего записей: {total_count}. Удалено просроченных: {expired_count}. Актуальных: {total_count - expired_count}")
    except Exception as e:
        print(f"Ошибка загрузки кэша из '{CACHE_FILE}': {e}. Запуск с пустым кэшем.")
        with cache_lock:
             cache = defaultdict(list)

def save_cache():
    print(f"Сохранение кэша в '{CACHE_FILE}'...")
    with cache_lock:
        cache_copy = cache.copy()
    try:
        with open(CACHE_FILE, "wb") as f:
            pickle.dump(dict(cache_copy), f)
        print(f"Кэш успешно сохранен ({len(cache_copy)} ключей).")
    except Exception as e:
        print(f"Ошибка сохранения кэша в '{CACHE_FILE}': {e}")

def add_to_cache_parsed(name_str: str, rtype: int, ttl: int, rdata_parsed: Any):
    if ttl <= 0 or rdata_parsed is None:
        return
    key = (normalize_name_str(name_str), rtype)
    expires_at = time.time() + ttl
    new_entry = (rdata_parsed, expires_at)
    with cache_lock:
        entries = cache[key]
        entries[:] = [entry for entry in entries if not (entry[0] == rdata_parsed)]
        entries.append(new_entry)

def get_from_cache(qname_str: str, qtype: int) -> List[Tuple[Any, int]]:
    key = (normalize_name_str(qname_str), qtype)
    current_time = time.time()
    results = []
    with cache_lock:
        if key in cache:
            valid_entries = []
            expired_exist = False
            for data, expires_at in cache[key]:
                if expires_at > current_time:
                    remaining_ttl = max(1, int(expires_at - current_time))
                    results.append((data, remaining_ttl))
                    valid_entries.append((data, expires_at))
                else:
                    expired_exist = True
            if expired_exist:
                if valid_entries:
                    cache[key] = valid_entries
                else:
                    del cache[key]
    return results

def cleanup_cache_loop():
    print("Запуск потока очистки кэша...")
    while running:
        time.sleep(60)
        if not running: break
        current_time = time.time()
        expired_keys = []
        expired_records_count = 0
        with cache_lock:
            keys_to_check = list(cache.keys())
            for key in keys_to_check:
                 if key not in cache: continue
                 entries = cache[key]
                 valid_entries = [(data, exp) for data, exp in entries if exp > current_time]
                 expired_records_count += len(entries) - len(valid_entries)
                 if not valid_entries:
                     expired_keys.append(key)
                 elif len(valid_entries) < len(entries):
                     cache[key] = valid_entries
            for key in expired_keys:
                if key in cache:
                    del cache[key]


# --- Обработчик запросов ---

def handle_request(data: bytes, addr: tuple, sock: socket.socket):
    start_time = time.time()
    request_id = None
    request_packet = None

    try:
        request_packet = Packet(data)

        if request_packet.parse_error or request_packet.header is None:
             print(f"Ошибка парсинга запроса от {addr}. Игнорирование.")
             return

        header = request_packet.header
        request_id = header.id

        if header.qr != 0:
            print(f"[{request_id}] Предупреждение: Получен пакет с флагом QR=1 от {addr}. Игнорирование.")
            return

        if header.qdcount != 1 or not request_packet.questions:
            print(f"[{request_id}] Предупреждение: Запрос от {addr} с qdcount={header.qdcount} != 1 или без вопросов. Отправка FORMERR.")
            error_response = request_packet.build_response_packet([], rcode=1)
            if error_response: sock.sendto(error_response, addr)
            return

        question = request_packet.questions[0]
        qname_obj = question.name
        qname_str_norm = normalize_name_str(qname_obj.value)
        qtype = question.q_type
        qclass = question.q_class
        qtype_text = get_str_type(qtype)

        if qclass != 1:
             print(f"[{request_id}] Предупреждение: Запрос для класса {qclass} != IN от {addr}. Отправка REFUSED.")
             error_response = request_packet.build_response_packet([], rcode=5)
             if error_response: sock.sendto(error_response, addr)
             return

        print(f"[{request_id}] Запрос от {addr}: {qname_obj.value} {qtype_text}")
        cached_results = get_from_cache(qname_str_norm, qtype)

        if cached_results:
            print(f"[{request_id}] Ответ из кэша для {qname_obj.value} {qtype_text}")
            answer_records = []
            for rdata_parsed, ttl in cached_results:
                 record = Record.__new__(Record)
                 record.name = Name(name=qname_str_norm)
                 record.ans_type_int = qtype
                 record.ans_type_str = get_str_type(qtype)
                 record.ans_class = qclass
                 record.ttl = ttl
                 record.rec_data = rdata_parsed


                 answer_records.append(record)

            response_data = request_packet.build_response_packet(answer_records, rcode=0)
            if response_data:
                sock.sendto(response_data, addr)
                print(f"[{request_id}] Ответ из кэша отправлен ({len(answer_records)} записей)")
            else:
                 print(f"[{request_id}] Ошибка сборки ответа из кэша.")
                 error_response = request_packet.build_response_packet([], rcode=2)
                 if error_response: sock.sendto(error_response, addr)


        else:
            print(f"[{request_id}] Кэш промах. Пересылка запроса {qname_obj.value} {qtype_text} к {UPSTREAM_RESOLVER}")
            upstream_sock = None
            try:
                upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                upstream_sock.settimeout(5.0)
                upstream_sock.sendto(data, (UPSTREAM_RESOLVER, UPSTREAM_PORT))
                upstream_response_data, upstream_addr = upstream_sock.recvfrom(4096)

                response_packet = Packet(upstream_response_data)

                if response_packet.parse_error or response_packet.header is None:
                     print(f"[{request_id}] Ошибка: Не удалось распарсить ответ от апстрима {upstream_addr}.")
                     error_response = request_packet.build_response_packet([], rcode=2)
                     if error_response: sock.sendto(error_response, addr)
                     return

                if response_packet.header.id != request_id:
                    print(f"[{request_id}] Ошибка: ID ответа ({response_packet.header.id}) от апстрима не совпадает с ID запроса ({request_id})")
                    error_response = request_packet.build_response_packet([], rcode=2)
                    if error_response: sock.sendto(error_response, addr)
                    return

                print(f"[{request_id}] Ответ получен от {upstream_addr}. Кэширование...")
                cached_count = 0
                all_records = response_packet.ans_records + response_packet.auth_records + response_packet.add_records
                for record in all_records:
                     if record.ans_class == 1 and record.rec_data is not None:
                         add_to_cache_parsed(record.name.value, record.ans_type_int, record.ttl, record.rec_data)
                         cached_count += 1

                print(f"[{request_id}] Закэшировано {cached_count} записей.")

                sock.sendto(upstream_response_data, addr)

            except socket.timeout:
                print(f"[{request_id}] Ошибка: Таймаут при ожидании ответа от {UPSTREAM_RESOLVER}")
                error_response = request_packet.build_response_packet([], rcode=2)
                if error_response: sock.sendto(error_response, addr)
            except Exception as e:
                print(f"[{request_id}] Неожиданная ошибка при работе с апстримом {UPSTREAM_RESOLVER}: {e}")
                if request_packet:
                     error_response = request_packet.build_response_packet([], rcode=2)
                     if error_response: sock.sendto(error_response, addr)
            finally:
                if upstream_sock:
                    upstream_sock.close()

        end_time = time.time()
        req_id_str = f"[{request_id}]" if request_id is not None else "[ID ???]"
        print(f"{req_id_str} Запрос обработан за {end_time - start_time:.4f} сек.")

    except Exception as e:
        req_id_str = f"[{request_id}]" if request_id is not None else "[ID ???]"
        print(f"{req_id_str} КРИТИЧЕСКАЯ ОШИБКА обработки запроса от {addr}: {e}")
        if request_packet and not request_packet.parse_error and request_packet.header:
            try:
                 error_response = request_packet.build_response_packet([], rcode=2) # RCODE=SERVFAIL
                 if error_response: sock.sendto(error_response, addr)
            except Exception as send_err:
                print(f"{req_id_str} Ошибка при отправке SERVFAIL клиенту {addr}: {send_err}")

def run_server():
    global running
    load_cache()
    cleanup_thread = threading.Thread(target=cleanup_cache_loop, daemon=True)
    cleanup_thread.start()
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((LISTEN_IP, LISTEN_PORT))
        print(f"DNS сервер запущен на {LISTEN_IP}:{LISTEN_PORT} (UDP)")
        print(f"Пересылка запросов на {UPSTREAM_RESOLVER}:{UPSTREAM_PORT}")
        print(f"Файл кэша: {CACHE_FILE}")
        print("Нажмите Ctrl+C для остановки.")
        while running:
            try:
                server_socket.settimeout(1.0)
                data, addr = server_socket.recvfrom(4096)
                handler_thread = threading.Thread(target=handle_request, args=(data, addr, server_socket))
                handler_thread.daemon = True
                handler_thread.start()
            except socket.timeout:
                 continue
            except Exception as e:
                 if running:
                     print(f"Ошибка в основном цикле сервера: {e}")
    except PermissionError:
        print(f"Ошибка: Недостаточно прав для прослушивания порта {LISTEN_PORT}.")
    except OSError as e:
         print(f"Ошибка привязки сокета к {LISTEN_IP}:{LISTEN_PORT}: {e}")
    except KeyboardInterrupt:
        print("\nПолучен сигнал Ctrl+C, завершение работы...")
    finally:
        running = False
        print("Ожидание завершения фоновых потоков...")
        save_cache()
        print("Сервер остановлен.")

if __name__ == "__main__":
    run_server()
