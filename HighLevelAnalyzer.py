from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# Definizione dei tipi di frame conosciuti
FRAME_TYPES = {
    0b000: "Ping",
    0b001: "Data",
    0b010: "ACK",
    0b011: "NAK"
}

class Hla(HighLevelAnalyzer):
    result_types = {
        "fsi_frame": {
            "format": "FSI Frame | Type: {frame_type} | User Data: {user_data} | Data Words: {data_words} | CRC: {crc} | Frame Tag: {frame_tag}"
        }
    }

    def decode(self, frame: AnalyzerFrame):
        """ Decodifica un frame FSI secondo la tabella 32-8 """

        # Ottieni i dati dal segnale acquisito
        data = frame.data["data"]

        if len(data) < 6:
            return None  # Il frame è troppo corto per essere valido

        # Estrazione dei campi FSI
        preamble = (data[0] >> 4) & 0xF  # Primi 4 bit devono essere 1111
        sof = data[0] & 0xF  # Secondi 4 bit devono essere 1001
        frame_type = (data[1] >> 5) & 0x7  # 3 bit
        user_data = data[2]  # 8 bit

        # Se è un PING, non ha Data Words
        if frame_type == 0b000:
            num_data_words = 0
            data_words = []
            crc_index = 3  # CRC subito dopo User Data
        else:
            num_data_words = len(data) - 6  # Escludiamo header, CRC, FrameTag, EOF, Postamble
            data_words = data[3:3 + num_data_words]  # Parole dati
            crc_index = 3 + num_data_words  # Il CRC è subito dopo i dati

        crc = data[crc_index]  # Byte CRC
        frame_tag = (data[crc_index + 1] >> 4) & 0xF  # 4 bit
        eof = (data[crc_index + 1] & 0xF)  # Ultimi 4 bit del penultimo byte
        postamble = (data[crc_index + 2] >> 4) & 0xF  # 4 bit

        # Verifica validità
        if preamble != 0xF or sof != 0x9 or eof != 0b0110 or postamble != 0xF:
            return None  # Frame non valido

        # Crea un frame leggibile per Saleae
        return AnalyzerFrame(
            "fsi_frame",
            frame.start_time,
            frame.end_time,
            {
                "frame_type": FRAME_TYPES.get(frame_type, "Unknown"),
                "user_data": hex(user_data),
                "data_words": " ".join(hex(b) for b in data_words) if data_words else "None",
                "crc": hex(crc),
                "frame_tag": hex(frame_tag)
            }
        )
