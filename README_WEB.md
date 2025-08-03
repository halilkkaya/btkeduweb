# Eğitim Asistanı Web Uygulaması

Gemini CLI yapısını kullanarak oluşturulmuş modern web tabanlı eğitim asistanı.

## Özellikler

- **Modern Web Arayüzü**: Bootstrap 5 ile responsive tasarım
- **Login Sistemi**: Kullanıcı girişi (şimdilik basit doğrulama)
- **Geç Tuşu**: Direkt yapay zeka asistanına erişim
- **Gerçek Zamanlı Chat**: AJAX ile anlık mesajlaşma
- **Dosya Yükleme**: Ses, video, PDF ve resim dosyaları
- **Drag & Drop**: Sürükle-bırak dosya yükleme
- **MCP Entegrasyonu**: Gemini + MCP araçları ile güçlü AI
- **Session Yönetimi**: Flask-Session ile oturum kontrolü

## Kurulum

### 1. Gereksinimler

```bash
pip install -r requirements.txt
```

### 2. Çevre Değişkenleri

`.env` dosyası oluşturun:

```env
GEMINI_API_KEY=your_gemini_api_key_here
MCP_URL=https://your-mcp-server-url/mcp
SECRET_KEY=your_secret_key_here
```

### 3. Çalıştırma

```bash
python web_app.py
```

Uygulama `http://localhost:5000` adresinde çalışacak.

## Kullanım

### Login Sayfası
- Kullanıcı adı ve şifre ile giriş yapabilirsiniz
- Herhangi bir kullanıcı adı/şifre kombinasyonu çalışır (şimdilik)
- **Geç** tuşu ile direkt chat'e erişebilirsiniz

### Chat Sayfası
- Modern sohbet arayüzü
- Gerçek zamanlı mesajlaşma
- Typing indicator
- Responsive tasarım

### Dosya Yükleme
- **Desteklenen Formatlar**:
  - **Ses**: MP3, WAV, M4A, AAC, OGG
  - **Video**: MP4, AVI, MOV, MKV, WEBM
  - **Belge**: PDF, TXT, DOC, DOCX
  - **Resim**: JPG, JPEG, PNG, GIF, BMP
- **Maksimum Boyut**: 100MB
- **Yükleme Yöntemleri**:
  - Dosya seç butonu
  - Sürükle-bırak
  - Çift tıklama

## Dosya Yapısı

```
edumcp/
├── web_app.py              # Ana Flask uygulaması
├── templates/
│   ├── base.html           # Temel HTML şablonu
│   ├── login.html          # Login sayfası
│   └── chat.html           # Chat sayfası
├── uploads/                # Yüklenen dosyalar
├── gemini_cli.py           # Orijinal CLI uygulaması
└── requirements.txt        # Gereksinimler
```

## API Endpoints

- `GET /` - Ana sayfa (login)
- `POST /login` - Giriş işlemi
- `GET /gec` - Geç tuşu (direkt chat)
- `GET /chat` - Chat sayfası
- `POST /api/chat` - Chat API
- `POST /upload` - Dosya yükleme
- `POST /clear-file` - Dosya temizleme
- `GET /logout` - Çıkış

## Özellikler

### Güvenlik
- Session tabanlı oturum yönetimi
- CSRF koruması (Flask ile)
- Input validasyonu
- Güvenli dosya adlandırma
- Dosya türü kontrolü

### Kullanıcı Deneyimi
- Modern gradient tasarım
- Smooth animasyonlar
- Responsive layout
- Loading indicators
- Drag & drop dosya yükleme
- Dosya bilgisi gösterimi

### AI Entegrasyonu
- Gemini 2.5 Pro modeli
- MCP araçları entegrasyonu
- Asenkron işlemler
- Hata yönetimi
- Dosya işleme araçları

### Dosya İşleme
- Otomatik dosya türü algılama
- Benzersiz dosya adlandırma
- Kullanıcı bazlı dosya yönetimi
- Session'da dosya bilgisi saklama
- MCP araçları ile entegrasyon

## Geliştirme

### Yeni Özellik Ekleme
1. `web_app.py`'de yeni route ekleyin
2. `templates/` klasöründe HTML şablonu oluşturun
3. CSS/JS dosyalarını `base.html`'e ekleyin

### Stil Değişiklikleri
- `templates/base.html` içindeki `<style>` bölümünü düzenleyin
- Bootstrap 5 sınıflarını kullanın
- Responsive tasarım için Bootstrap grid sistemini kullanın

### Dosya Yükleme Özelleştirme
- `ALLOWED_EXTENSIONS` sözlüğünü düzenleyin
- `MAX_CONTENT_LENGTH` değerini değiştirin
- Yeni dosya türleri ekleyin

## Sorun Giderme

### Yaygın Hatalar

1. **ModuleNotFoundError**: `pip install -r requirements.txt` çalıştırın
2. **API Key Hatası**: `.env` dosyasını kontrol edin
3. **Port Hatası**: Farklı port kullanın: `app.run(port=5001)`
4. **Dosya Yükleme Hatası**: Dosya boyutunu ve türünü kontrol edin
5. **Uploads Klasörü**: Klasörün yazma izni olduğundan emin olun

### Debug Modu
```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

## Gelecek Özellikler

- [x] Dosya yükleme sistemi
- [x] Drag & drop desteği
- [x] MCP araçları entegrasyonu
- [ ] Veritabanı entegrasyonu
- [ ] Kullanıcı kayıt sistemi
- [ ] Chat geçmişi
- [ ] Çoklu dil desteği
- [ ] Admin paneli
- [ ] Dosya önizleme
- [ ] Çoklu dosya yükleme 