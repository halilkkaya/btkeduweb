# web_app.py
import os
import time
import json
import asyncio
import hashlib
import bcrypt
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_session import Session
from werkzeug.utils import secure_filename
import mysql.connector
from mysql.connector import Error

# --- 3p SDK'ler --------------------------------------------------------------
from google import genai                         # Google Gemini SDK
from google.genai import types
from fastmcp import Client                       # MCP istemcisi
# -----------------------------------------------------------------------------

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "gizli-anahtar-123")
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Database bağlantı ayarları
DB_CONFIG = {
    'host': os.getenv("DB_HOST", "localhost"),
    'user': os.getenv("DB_USER", "root"),
    'password': os.getenv("DB_PASSWORD", ""),
    'database': os.getenv("DB_NAME", "education_mcp"),
    'charset': 'utf8mb4'
}

def get_db_connection():
    """Database bağlantısı oluştur"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Database bağlantı hatası: {e}")
        return None

def hash_password(password):
    """Şifreyi hash'le"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    """Şifre kontrolü"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def verify_user(username, password):
    """Kullanıcı doğrulama"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s AND is_active = TRUE", (username,))
        user = cursor.fetchone()
        
        if user and check_password(password, user['password_hash']):
            # Son giriş zamanını güncelle
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user['id'],))
            conn.commit()
            return user
        return None
    except Error as e:
        print(f"Kullanıcı doğrulama hatası: {e}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def get_user_by_id(user_id):
    """ID ile kullanıcı getir"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()
    except Error as e:
        print(f"Kullanıcı getirme hatası: {e}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def update_user_plan(user_id, plan_type):
    """Kullanıcı planını güncelle"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET plan_type = %s WHERE id = %s", (plan_type, user_id))
        conn.commit()
        return True
    except Error as e:
        print(f"Plan güncelleme hatası: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def get_user_chat_sessions(user_id):
    """Kullanıcının chat session'larını getir"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM chat_sessions WHERE user_id = %s AND is_active = TRUE ORDER BY last_activity DESC",
            (user_id,)
        )
        return cursor.fetchall()
    except Error as e:
        print(f"Chat session getirme hatası: {e}")
        return []
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def create_chat_session(user_id, session_name="Yeni Chat"):
    """Yeni chat session oluştur"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        # Benzersiz session_id oluştur
        import uuid
        session_id = str(uuid.uuid4())
        
        cursor.execute(
            "INSERT INTO chat_sessions (user_id, session_id, session_name) VALUES (%s, %s, %s)",
            (user_id, session_id, session_name)
        )
        conn.commit()
        return cursor.lastrowid
    except Error as e:
        print(f"Chat session oluşturma hatası: {e}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def get_chat_session(session_id):
    """Chat session bilgilerini getir"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM chat_sessions WHERE id = %s", (session_id,))
        return cursor.fetchone()
    except Error as e:
        print(f"Chat session getirme hatası: {e}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def update_chat_session_activity(session_id):
    """Chat session aktivite zamanını güncelle"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = %s",
            (session_id,)
        )
        conn.commit()
        return True
    except Error as e:
        print(f"Chat session güncelleme hatası: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def delete_chat_session(session_id, user_id):
    """Chat session'ı sil (soft delete)"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_sessions SET is_active = FALSE WHERE id = %s AND user_id = %s",
            (session_id, user_id)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Error as e:
        print(f"Chat session silme hatası: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def get_chat_messages(session_id, limit=50):
    """Chat session'ındaki mesajları getir"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM chat_messages WHERE chat_session_id = %s ORDER BY created_at ASC LIMIT %s",
            (session_id, limit)
        )
        return cursor.fetchall()
    except Error as e:
        print(f"Chat mesajları getirme hatası: {e}")
        return []
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def save_chat_message(session_id, user_id, message_type, content):
    """Chat mesajını kaydet"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO chat_messages (chat_session_id, user_id, message_type, content) VALUES (%s, %s, %s, %s)",
            (session_id, user_id, message_type, content)
        )
        conn.commit()
        
        # Session aktivite zamanını güncelle
        update_chat_session_activity(session_id)
        return True
    except Error as e:
        print(f"Mesaj kaydetme hatası: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def save_uploaded_file_db(user_id, filename, original_filename, file_path, file_type, file_size):
    """Yüklenen dosya bilgisini database'e kaydet"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO uploaded_files (user_id, filename, original_filename, file_path, file_type, file_size) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, filename, original_filename, file_path, file_type, file_size)
        )
        conn.commit()
        return True
    except Error as e:
        print(f"Dosya kaydetme hatası: {e}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Dosya yükleme ayarları
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {
    'audio': {'mp3', 'wav', 'm4a', 'aac', 'ogg'},
    'video': {'mp4', 'avi', 'mov', 'mkv', 'webm'},
    'document': {'pdf', 'txt', 'doc', 'docx'},
    'image': {'jpg', 'jpeg', 'png', 'gif', 'bmp'}
}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max

# --------------------------- Ortam / Bağlantılar -----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MCP_URL        = os.getenv("MCP_URL")      # ngrok vb. "https://.../mcp"

if not GEMINI_API_KEY or not MCP_URL:
    raise RuntimeError("GEMINI_API_KEY ve MCP_URL .env'de tanımlı olmalı!")

# Gemini istemcisi (asenkron API'ye ihtiyacımız var → .aio alt-modülü)
gemini = genai.Client(api_key=GEMINI_API_KEY)

# Uzak MCP sunucusuna bağlanacak FastMCP istemcisi
mcp_client = Client(
    MCP_URL
    # token yoksa BearerAuth'ı atlamak için koşullu ekle
    )

MCP = {
    "type": "url",
    "url": os.getenv("MCP_URL"),
    "name": "Eğitim Asistanı"
    }

# --------------------------- S# ===============================================
SYSTEM_PROMPT = """
Eğitim Asistanısın. Kullanıcının sorusuna cevap ver. gerekli toolları çağır.
sadece tooları kullanıp cevap vereceksin tool kullanmaman yasak. 
kullanıcı sana dosya yolu verdiğinde dosya yolunu MCP araçlarına parametre olarak geçir. 
dosya yollarını kullanman çok önemli.

DOSYA İŞLEME KURALLARI:
- Yüklenen dosyalar için MCP Yolu bilgisini kullan
- Dosya yolu formatı: /tam/yol/dosyaadi.pdf şeklinde olacak
- PDF dosyaları için pdf_ozetle tool'unu kullan
- Ses dosyaları için ses_dosyasini_transkript_et tool'unu kullan  
- Video dosyaları için videoyu_ozetle tool'unu kullan
- Dosya yolunu MCP araçlarına parametre olarak geçir
- Dosya yolu [Yüklenen dosya: dosyaadi.pdf (document) - MCP Yolu: /tam/yol/dosyaadi.pdf] formatında gelir

WEB ÇIKTI FORMATI:
- JSON verilerini web için uygun formata çevir
- Markdown formatında başlıklar kullan (**Başlık**)
- Listeler için bullet points kullan
- Önemli bilgileri **kalın** yap
- Bölümler arası ayırıcılar kullan (---)
- Okunabilir ve düzenli format sağla
"""

# --------------------------- JSON Format Dönüştürme Fonksiyonları --------------
def format_pdf_summary(json_data):
    """PDF özet JSON'unu web formatına çevir"""
    try:
        data = json.loads(json_data) if isinstance(json_data, str) else json_data
        
        if data.get("durum") == "Hata":
            return f"**Hata:** {data.get('mesaj', 'Bilinmeyen hata')}"
        
        analysis = data.get("belge_analizi", {})
        
        output = f"""
### **{analysis.get('baslik', 'PDF Analizi')}**

**Belge Türü:** {analysis.get('belge_tipi', 'Bilinmiyor')}  
**Dil:** {analysis.get('belge_dili', 'Tespit edilemedi')}

---

### **Kısa Özet**
{analysis.get('kisa_ozet', 'Özet bulunamadı')}

---

### **Detaylı Analiz**
{analysis.get('genis_ozet', 'Detaylı analiz bulunamadı')}

---

### **Sayfa Özetleri**
"""
        
        for sayfa in analysis.get('sayfa_ozetleri', []):
            output += f"""
**Sayfa {sayfa.get('sayfa', 'Bilinmiyor')}:** {sayfa.get('konu', 'Bilinmiyor')}
{sayfa.get('aciklama', '')}
"""
        
        if analysis.get('kilit_ogrenme_noktalari'):
            output += "\n### **Kilit Öğrenme Noktaları**\n"
            for nokta in analysis['kilit_ogrenme_noktalari']:
                output += f"• {nokta}\n"
        
        if analysis.get('tablolar_ve_grafikler'):
            output += "\n### **Tablolar ve Grafikler**\n"
            for tablo in analysis['tablolar_ve_grafikler']:
                output += f"• {tablo}\n"
        
        if analysis.get('bahsedilen_kaynaklar'):
            output += "\n### **Bahsedilen Kaynaklar**\n"
            for kaynak in analysis['bahsedilen_kaynaklar']:
                output += f"• {kaynak}\n"
        
        if analysis.get('anahtar_kelimeler'):
            output += "\n### **Anahtar Kelimeler**\n"
            for kelime in analysis['anahtar_kelimeler']:
                output += f"• {kelime}\n"
        
        if analysis.get('ogrenme_ciktilari'):
            output += "\n### **Öğrenme Çıktıları**\n"
            for cikti in analysis['ogrenme_ciktilari']:
                output += f"• {cikti}\n"
        
        if analysis.get('belge_sonrasi_ogrenilecekler'):
            output += f"\n### **Bu Belgeyi Okuduktan Sonra Öğrenecekleriniz**\n{analysis['belge_sonrasi_ogrenilecekler']}"
        
        return output.strip()
        
    except Exception as e:
        return f"**Format Hatası:** JSON verisi işlenirken hata oluştu: {str(e)}"

def format_audio_transcript(json_data):
    """Ses transkript JSON'unu web formatına çevir"""
    try:
        data = json.loads(json_data) if isinstance(json_data, str) else json_data
        
        if data.get("durum") == "Hata":
            return f"**Hata:** {data.get('mesaj', 'Bilinmeyen hata')}"
        
        analysis = data.get("ses_analizi", {})
        
        output = f"""
### **Ses Analizi**

**Ses Dili:** {analysis.get('ses_dili', 'Tespit edilemedi')}  
**Süre:** {analysis.get('sure', 'Bilinmiyor')}  
**Konuşmacı Sayısı:** {analysis.get('konusmaci_sayisi', 'Bilinmiyor')}  
**Kalite:** {analysis.get('kalite_degerlendirmesi', 'Bilinmiyor')}

---

### **Transkript**
{analysis.get('transkript', 'Transkript bulunamadı')}

---

### **Özet**
{analysis.get('detayli_ozet', analysis.get('kisa_transkript', 'Özet bulunamadı'))}

---

### **Önemli Noktalar**
"""
        
        for nokta in analysis.get('onemli_noktalar', []):
            output += f"• {nokta}\n"
        
        if analysis.get('zaman_damgalari'):
            output += "\n### **Zaman Damgaları**\n"
            for zaman in analysis['zaman_damgalari']:
                output += f"**{zaman.get('zaman', 'Bilinmiyor')}:** {zaman.get('konu', 'Bilinmiyor')} ({zaman.get('onem', 'Bilinmiyor')} önem)\n"
        
        if analysis.get('konusmaci_analizi'):
            konusmaci = analysis['konusmaci_analizi']
            output += f"""
### **Konuşmacı Analizi**
**Konuşmacı Sayısı:** {konusmaci.get('konusmaci_sayisi', 'Bilinmiyor')}  
**Roller:** {', '.join(konusmaci.get('konusmaci_rolleri', []))}  
**Konuşma Tarzı:** {konusmaci.get('konusma_tarzi', 'Bilinmiyor')}
"""
        
        if analysis.get('anahtar_kelimeler'):
            output += "\n### **Anahtar Kelimeler**\n"
            for kelime in analysis['anahtar_kelimeler']:
                output += f"• {kelime}\n"
        
        if analysis.get('ogrenme_ciktilari'):
            output += "\n### **Öğrenme Çıktıları**\n"
            for cikti in analysis['ogrenme_ciktilari']:
                output += f"• {cikti}\n"
        
        return output.strip()
        
    except Exception as e:
        return f"**Format Hatası:** JSON verisi işlenirken hata oluştu: {str(e)}"

def format_quiz_questions(json_data):
    """Quiz soruları JSON'unu web formatına çevir"""
    try:
        data = json.loads(json_data) if isinstance(json_data, str) else json_data
        
        if data.get("durum") == "Hata":
            return f"**Hata:** {data.get('mesaj', 'Bilinmeyen hata')}"
        
        quiz = data.get("soru_seti", {})
        
        output = f"""
### **{quiz.get('konu', 'Quiz')} - Soru Seti**

**Soru Sayısı:** {quiz.get('soru_sayisi', 0)}  
**Zorluk Seviyesi:** {quiz.get('zorluk_seviyesi', 'Bilinmiyor')}  
**Soru Tipi:** {quiz.get('soru_tipi', 'Bilinmiyor')}
**Web Arama:** {'✅ Aktif' if quiz.get('web_arama_yapildi', False) else '❌ Pasif'}

---

"""
        
        for i, soru in enumerate(quiz.get('sorular', []), 1):
            output += f"""
### **Soru {i}**
**Tip:** {soru.get('tip', 'Bilinmiyor')} | **Zorluk:** {soru.get('zorluk', 'Bilinmiyor')}

**Soru:** {soru.get('soru', 'Soru metni bulunamadı')}

"""
            
            if soru.get('secenekler'):
                output += "**Seçenekler:**\n"
                for secenek in soru['secenekler']:
                    output += f"• {secenek}\n"
            
            output += f"""
**Doğru Cevap:** {soru.get('dogru_cevap', 'Bilinmiyor')}

**Açıklama:** {soru.get('aciklama', 'Açıklama bulunamadı')}

**Öğrenme Hedefi:** {soru.get('ogrenme_hedefi', 'Bilinmiyor')}

**Kaynak:** {soru.get('kaynak_bilgisi', 'Model bilgileri')}

---
"""
        
        genel = quiz.get('genel_bilgiler', {})
        if genel:
            output += f"""
### **Genel Bilgiler**
**Toplam Puan:** {genel.get('toplam_puan', 'Bilinmiyor')}  
**Tahmini Süre:** {genel.get('sure_tahmini', 'Bilinmiyor')}

**Konu Dağılımı:**
"""
            for dagilim in genel.get('konu_dagilimi', []):
                output += f"• {dagilim}\n"
            
            output += "\n**Zorluk Dağılımı:**\n"
            for dagilim in genel.get('zorluk_dagilimi', []):
                output += f"• {dagilim}\n"
            
            if genel.get('tavsiyeler'):
                output += "\n**Tavsiyeler:**\n"
                for tavsiye in genel['tavsiyeler']:
                    output += f"• {tavsiye}\n"
            
            if genel.get('kaynak_onerileri'):
                output += "\n**Kaynak Önerileri:**\n"
                for kaynak in genel['kaynak_onerileri']:
                    output += f"• {kaynak}\n"
            
            # Web arama sonuçları
            web_sonuclari = genel.get('web_arama_sonuclari', {})
            if web_sonuclari and web_sonuclari.get('arama_yapildi'):
                output += f"""
### **Web Arama Sonuçları**
**Arama Durumu:** ✅ Aktif  
**Bulunan Kaynak Sayısı:** {web_sonuclari.get('bulunan_kaynak_sayisi', 0)}

**Kullanılan Kaynaklar:**
"""
                for kaynak in web_sonuclari.get('kullanilan_kaynaklar', []):
                    output += f"• {kaynak}\n"
        
        return output.strip()
        
    except Exception as e:
        return f"**Format Hatası:** JSON verisi işlenirken hata oluştu: {str(e)}"

def format_ai_response(response_text):
    """AI yanıtını web formatına çevir"""
    # JSON içerik olup olmadığını kontrol et
    if response_text.startswith('{') or response_text.startswith('['):
        try:
            # PDF özeti kontrolü
            if '"belge_analizi"' in response_text:
                return format_pdf_summary(response_text)
            # Ses transkript kontrolü
            elif '"ses_analizi"' in response_text:
                return format_audio_transcript(response_text)
            # Quiz soruları kontrolü
            elif '"soru_seti"' in response_text:
                return format_quiz_questions(response_text)
            else:
                # Genel JSON formatı
                data = json.loads(response_text)
                return json.dumps(data, indent=2, ensure_ascii=False)
        except:
            pass
    
    # Normal metin ise markdown formatına çevir
    return response_text

# --------------------------- Dosya İşleme Fonksiyonları ----------------------
def allowed_file(filename, file_type=None):
    """Dosya uzantısını kontrol et"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    
    if file_type:
        return ext in ALLOWED_EXTENSIONS.get(file_type, set())
    
    # Tüm izin verilen uzantıları kontrol et
    for extensions in ALLOWED_EXTENSIONS.values():
        if ext in extensions:
            return True
    return False

def get_file_type(filename):
    """Dosya türünü belirle"""
    if '.' not in filename:
        return None
    ext = filename.rsplit('.', 1)[1].lower()
    
    for file_type, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return file_type
    return None

def save_uploaded_file(file, user_id):
    """Yüklenen dosyayı kaydet"""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Kullanıcı ID'si ile benzersiz dosya adı oluştur
        timestamp = int(time.time())
        user_filename = f"{user_id}_{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], user_filename)
        file.save(filepath)
        return filepath, filename
    return None, None

def get_file_path_for_mcp(filepath):
    """MCP araçları için dosya yolunu hazırla"""
    # MCP araçları için tam dosya yolunu döndür
    if os.path.exists(filepath):
        # Mutlak yol olarak döndür
        return os.path.abspath(filepath)
    else:
        # Eğer dosya bulunamazsa, sadece dosya adını döndür
        return os.path.basename(filepath)

def get_user_model(user_id):
    """Kullanıcının planına göre model seç"""
    if user_id == 0:  # Guest kullanıcı
        return "gemini-1.5-pro"
    
    user = get_user_by_id(user_id)
    if user and user.get('plan_type') == 'pro':
        return "gemini-2.5-pro"
    else:
        return "gemini-1.5-pro"

# --------------------------- Ana LLM Çağrısı ---------------------------------
async def ai_chat(messages, system_prompt, user_id=0):
    """
    Gemini + MCP ile sohbet
    """
    try:
        # Kullanıcının planına göre model seç
        model_name = get_user_model(user_id)
        
        # 1) MCP oturumunu aç → session otomatik keşif + araç çağrıları
        async with mcp_client:
            # 2) Mesajları Gemini formatında düzenle
            content_list = []
            
            # Sistem promptu ilk kullanıcı mesajıyla birleştir
            if messages:
                first_user_msg = messages[0]["content"]
                system_with_user = f"{system_prompt}\n\nKullanıcı: {first_user_msg}"
                content_list.append(
                    types.Content(role="user", parts=[types.Part(text=system_with_user)])
                )
                
                # Geri kalan mesajları ekle
                for msg in messages[1:]:
                    role = "model" if msg["role"] == "assistant" else "user"
                    content_list.append(
                        types.Content(role=role, parts=[types.Part(text=msg["content"])])
                    )

            # 3) Gemini'ye istek gönder
            response = await gemini.aio.models.generate_content(
                model=model_name,
                contents=content_list,
                config=types.GenerateContentConfig(
                    tools=[mcp_client.session],   # MCP araç listesini ekle
                    max_output_tokens=8192*2, 
                    temperature=0.5,
                )
            )

            content_out = response.text if response.text else ""
            return content_out.strip()

    except Exception as e:
        print(f"Hata oluştu: {e}")
        return f"Hata oluştu: {e}"

# --------------------------- Flask Routes -------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return render_template('login.html', error="Kullanıcı adı ve şifre gerekli!")
    
    user = verify_user(username, password)
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['full_name'] = user['full_name']
        session['plan_type'] = user.get('plan_type', 'free')
        return redirect(url_for('chat'))
    else:
        return render_template('login.html', error="Kullanıcı adı veya şifre hatalı!")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        
        if not username or not password:
            return render_template('register.html', error="Kullanıcı adı ve şifre gerekli!")
        
        # Kullanıcı kaydı
        conn = get_db_connection()
        if conn:
            try:
                cursor = conn.cursor()
                hashed_password = hash_password(password)
                cursor.execute(
                    "INSERT INTO users (username, password_hash, email, full_name, plan_type) VALUES (%s, %s, %s, %s, %s)",
                    (username, hashed_password, email, full_name, 'free')
                )
                conn.commit()
                flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
                return redirect(url_for('index'))
            except Error as e:
                if "Duplicate entry" in str(e):
                    return render_template('register.html', error="Bu kullanıcı adı zaten kullanılıyor!")
                else:
                    return render_template('register.html', error="Kayıt sırasında hata oluştu!")
            finally:
                if conn.is_connected():
                    cursor.close()
                    conn.close()
        else:
            return render_template('register.html', error="Database bağlantı hatası!")
    
    return render_template('register.html')

@app.route('/gec')
def gec():
    """Geç tuşu ile direkt chat'e yönlendir"""
    session['user_id'] = 0  # Guest user
    session['username'] = 'Misafir'
    session['role'] = 'guest'
    session['full_name'] = 'Misafir Kullanıcı'
    session['plan_type'] = 'free'
    return redirect(url_for('chat'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    # Aktif chat session'ı kontrol et
    current_session_id = session.get('current_chat_session_id')
    
    # Eğer aktif session yoksa yeni oluştur
    if not current_session_id:
        if session.get('user_id', 0) > 0:  # Guest değilse
            new_session_id = create_chat_session(session['user_id'])
            if new_session_id:
                session['current_chat_session_id'] = new_session_id
                current_session_id = new_session_id
    
    return render_template('chat.html', 
                         username=session.get('username', 'Misafir'),
                         full_name=session.get('full_name', 'Misafir'),
                         plan_type=session.get('plan_type', 'free'),
                         current_session_id=current_session_id)

@app.route('/chats')
def chats():
    """Chat listesi sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session.get('user_id', 0)
    if user_id == 0:  # Guest kullanıcı
        return redirect(url_for('chat'))
    
    chat_sessions = get_user_chat_sessions(user_id)
    return render_template('chats.html', 
                         username=session.get('username', 'Misafir'),
                         plan_type=session.get('plan_type', 'free'),
                         chat_sessions=chat_sessions)

@app.route('/chat/<int:session_id>')
def chat_session(session_id):
    """Belirli bir chat session'ına git"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    user_id = session.get('user_id', 0)
    chat_session = get_chat_session(session_id)
    
    if not chat_session or chat_session['user_id'] != user_id:
        flash('Chat bulunamadı!', 'error')
        return redirect(url_for('chats'))
    
    session['current_chat_session_id'] = session_id
    return redirect(url_for('chat'))

@app.route('/new-chat', methods=['POST'])
def new_chat():
    """Yeni chat oluştur"""
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekiyor'}), 401
    
    user_id = session.get('user_id', 0)
    if user_id == 0:  # Guest kullanıcı
        return jsonify({'error': 'Misafir kullanıcılar yeni chat oluşturamaz'}), 400
    
    data = request.get_json()
    session_name = data.get('session_name', 'Yeni Chat')
    
    new_session_id = create_chat_session(user_id, session_name)
    if new_session_id:
        session['current_chat_session_id'] = new_session_id
        return jsonify({
            'success': True, 
            'session_id': new_session_id,
            'session_name': session_name,
            'message': 'Yeni chat oluşturuldu!'
        })
    else:
        return jsonify({'error': 'Chat oluşturulamadı'}), 500

@app.route('/delete-chat/<int:session_id>', methods=['POST'])
def delete_chat(session_id):
    """Chat session'ı sil"""
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekiyor'}), 401
    
    user_id = session.get('user_id', 0)
    if user_id == 0:  # Guest kullanıcı
        return jsonify({'error': 'Misafir kullanıcılar chat silemez'}), 400
    
    if delete_chat_session(session_id, user_id):
        # Eğer silinen chat aktif chat ise, aktif chat'i temizle
        if session.get('current_chat_session_id') == session_id:
            session.pop('current_chat_session_id', None)
        
        return jsonify({'success': True, 'message': 'Chat silindi!'})
    else:
        return jsonify({'error': 'Chat silinemedi'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/pricing')
def pricing():
    """Plan seçenekleri sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('pricing.html', 
                         username=session.get('username', 'Misafir'),
                         plan_type=session.get('plan_type', 'free'))

@app.route('/payment')
def payment():
    """Ödeme sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('payment.html', 
                         username=session.get('username', 'Misafir'),
                         plan_type=session.get('plan_type', 'free'))

@app.route('/upgrade-to-pro', methods=['POST'])
def upgrade_to_pro():
    """Pro plana yükseltme"""
    if 'user_id' not in session or session.get('user_id', 0) == 0:
        return jsonify({'error': 'Misafir kullanıcılar pro plana yükseltemez'}), 400
    
    user_id = session.get('user_id')
    if update_user_plan(user_id, 'pro'):
        session['plan_type'] = 'pro'
        return jsonify({'success': True, 'message': 'Pro plana başarıyla yükseltildiniz!'})
    else:
        return jsonify({'error': 'Plan yükseltme sırasında hata oluştu'}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    """Dosya yükleme endpoint'i"""
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekiyor'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'Dosya seçilmedi'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Dosya seçilmedi'}), 400
    
    user_id = session.get('user_id', 0)
    filepath, filename = save_uploaded_file(file, user_id)
    
    if filepath:
        file_type = get_file_type(filename)
        file_size = os.path.getsize(filepath)
        mcp_path = get_file_path_for_mcp(filepath)
        
        print(f"DEBUG: Dosya yüklendi - Path: {filepath}, MCP Path: {mcp_path}")
        
        # Database'e kaydet
        if user_id > 0:  # Guest değilse
            save_uploaded_file_db(user_id, filename, file.filename, filepath, file_type, file_size)
        
        session['current_file'] = {
            'path': filepath,
            'name': filename,
            'type': file_type,
            'mcp_path': mcp_path
        }
        
        return jsonify({
            'success': True,
            'filename': filename,
            'type': file_type,
            'message': f'{filename} başarıyla yüklendi!'
        })
    else:
        return jsonify({'error': 'Geçersiz dosya türü'}), 400

@app.route('/api/chat', methods=['POST'])
def api_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekiyor'}), 401
    
    data = request.get_json()
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'Mesaj boş olamaz'}), 400
    
    # Aktif chat session'ı kontrol et
    current_session_id = session.get('current_chat_session_id')
    if not current_session_id:
        return jsonify({'error': 'Aktif chat session bulunamadı'}), 400
    
    # Session'ın kullanıcıya ait olduğunu kontrol et
    chat_session = get_chat_session(current_session_id)
    if not chat_session or chat_session['user_id'] != session.get('user_id', 0):
        return jsonify({'error': 'Geçersiz chat session'}), 400
    
    # Mesaj geçmişini database'den al
    chat_messages = get_chat_messages(current_session_id)
    messages = []
    
    for msg in chat_messages:
        messages.append({
            "role": "user" if msg['message_type'] == 'user' else "assistant",
            "content": msg['content']
        })
    
    # Yeni kullanıcı mesajını ekle
    messages.append({"role": "user", "content": user_message})
    
    # Eğer yüklenmiş dosya varsa, mesaja ekle
    current_file = session.get('current_file')
    if current_file:
        file_info = f"\n[Yüklenen dosya: {current_file['name']} ({current_file['type']}) - MCP Yolu: {current_file['mcp_path']}]"
        user_message += file_info
        print(f"DEBUG: Dosya bilgisi mesaja eklendi - {current_file['mcp_path']}")
    else:
        print("DEBUG: Yüklenen dosya bulunamadı")
    
    # Database'e kullanıcı mesajını kaydet
    if session.get('user_id', 0) > 0:
        save_chat_message(current_session_id, session['user_id'], 'user', user_message)
    
    # AI yanıtını al
    system_message = SYSTEM_PROMPT + """
    
    KRİTİK KURALLAR: 
    - JSON verisini okunaklı formata çevir
    - Sonuç yoksa sadece "Bulunamadı" de
    - Yüklenen dosyaları işlemek için uygun MCP araçlarını kullan
    - Dosya yollarını doğru şekilde kullan
    """
    
    # Asenkron fonksiyonu çalıştır
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        ai_response = loop.run_until_complete(ai_chat(messages, system_message, session.get('user_id', 0)))
    finally:
        loop.close()
    
    if ai_response and ai_response.strip():
        # AI yanıtını web formatına çevir
        formatted_response = format_ai_response(ai_response)
        
        # Database'e AI mesajını kaydet
        if session.get('user_id', 0) > 0:
            save_chat_message(current_session_id, session['user_id'], 'assistant', formatted_response)
        
        return jsonify({'response': formatted_response})
    else:
        return jsonify({'error': 'Asistan yanıt veremedi. Lütfen tekrar deneyin.'}), 500

@app.route('/clear-file', methods=['POST'])
def clear_file():
    """Yüklenen dosyayı temizle"""
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum açmanız gerekiyor'}), 401
    
    if 'current_file' in session:
        del session['current_file']
    
    return jsonify({'success': True, 'message': 'Dosya temizlendi'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 