import os
import time
import json
import asyncio
import hashlib
import bcrypt
import pymysql
from datetime import datetime
from dotenv import load_dotenv

# --- Web Framework -----------------------------------------------------------
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit

# --- 3p SDK'ler --------------------------------------------------------------
from google import genai                         # Google Gemini SDK
from google.genai import types
from fastmcp import Client                       # MCP istemcisi
# -----------------------------------------------------------------------------

load_dotenv()

# --------------------------- Flask Uygulaması --------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'egitim-asistan-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")

# --------------------------- Veritabanı Bağlantısı --------------------------
def get_db_connection():
    """Veritabanı bağlantısı oluştur"""
    return pymysql.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

# --------------------------- Ortam / Bağlantılar -----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MCP_URL        = os.getenv("MCP_URL")      # ngrok vb. "https://.../mcp"

if not GEMINI_API_KEY or not MCP_URL:
    raise RuntimeError("GEMINI_API_KEY ve MCP_URL .env'de tanımlı olmalı!")

# Gemini istemcisi
gemini = genai.Client(api_key=GEMINI_API_KEY)

MCP = {
    "type": "url",
    "url": os.getenv("MCP_URL"),
    "name": "Eğitim Asistanı"
}

def get_current_user_uploaded_file(user_id):
    """Mevcut kullanıcının en son yüklediği aktif dosyayı getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT file_path, file_type FROM uploaded_files 
            WHERE user_id = %s AND is_active = 1 
            ORDER BY uploaded_at DESC 
            LIMIT 1
            """
            cursor.execute(sql, (user_id,))
            result = cursor.fetchone()
            return result if result else None
    finally:
        conn.close()

# --------------------------- Sistem Prompt -----------------------------------
def get_system_prompt_free(user_id=None, session_id=None):
    """Free sürüm için sistem prompt'u oluştur"""
    file_path_info = ""
    
    if user_id and session_id:
        # Mevcut oturumun son dosya yolunu al
        current_file_path = get_current_session_file_path(session_id, user_id)
        if current_file_path:
            # Dosya bilgilerini al
            file_info = get_file_info_by_path(current_file_path)
            if file_info:
                import os
                dosya_adi = os.path.basename(file_info['file_path'])
                file_path_info = f"\n\nKULLANICI DOSYASI: {dosya_adi} ({file_info['file_type']})"
    
    return f"""
Eğitim Asistanısın (Free Sürüm). Kullanıcının sorusuna detaylı ve kapsamlı cevap ver. gerekli toolları çağır.

KRİTİK KURAL: Hiçbir işlemi tool kullanmadan yapma! Her işlem için uygun tool'u kullan.

DOSYA İŞLEME KURALLARI:
- Kullanıcının yüklediği dosyalar "C:\\mcpler\\education_mcp\\shared_uploads\\" klasöründe bulunur
- Eğer kullanıcı dosya yüklediyse, bu dosyayı işlemek için uygun tool'u kullan:
  * PDF dosyaları için: pdf_ozetle(dosya_adi, ozet_tipi="kapsamli", hedef_dil="Türkçe")
  * Ses dosyaları için: ses_dosyasini_transkript_et(dosya_adi, cikti_tipi="ozet", hedef_dil="Türkçe")
  * Video dosyaları için: videoyu_ozetle(video_dosyasi_yolu=dosya_adi, ozet_tipi="kapsamli", hedef_dil="Türkçe")
- Dosya adını tam yol olarak değil, sadece dosya adı olarak kullan
- Tool çağrısında dosya adını parametre olarak ver
- Kullanıcı "önceki dosyam", "daha önce yüklediğim dosya" gibi ifadeler kullanırsa, o dosyayı anlık olarak işle ve sonra sil
- Dosyalar sadece bir kez kullanılır, sonra otomatik olarak temizlenir

DİĞER İŞLEMLER İÇİN TOOL KULLANIMI:
- Quiz oluşturma için: soru_olustur(konu, soru_sayisi, zorluk, soru_tipi)
- Web araması için: soru_olustur fonksiyonunun web_arama parametresi
- Her işlem için mutlaka uygun tool'u çağır{file_path_info}

KRİTİK KURALLAR: 
- Hiçbir işlemi tool kullanmadan yapma!
- Her dosya işlemi için uygun tool'u kullan
- Her quiz oluşturma için soru_olustur tool'unu kullan
- Tool kullanmadan hiçbir cevap verme
- JSON verisini okunaklı formata çevir
- Sonuç yoksa "Bulunamadı" de
- Türkçe ve anlaşılır cevaplar ver
- Detaylı, kapsamlı ve uzun cevaplar ver
- Örnekler ve açıklamalar ekle
- Adım adım çözümler sun
"""

def get_system_prompt_pro(user_id=None, session_id=None):
    """Pro sürüm için sistem prompt'u oluştur"""
    file_path_info = ""
    
    if user_id and session_id:
        # Mevcut oturumun son dosya yolunu al
        current_file_path = get_current_session_file_path(session_id, user_id)
        if current_file_path:
            # Dosya bilgilerini al
            file_info = get_file_info_by_path(current_file_path)
            if file_info:
                import os
                dosya_adi = os.path.basename(file_info['file_path'])
                file_path_info = f"\n\nKULLANICI DOSYASI: {dosya_adi} ({file_info['file_type']})"
    
    return f"""
Eğitim Asistanısın (Pro Sürüm). Kullanıcının sorusuna detaylı ve kapsamlı cevap ver. gerekli toolları çağır.

KRİTİK KURAL: Hiçbir işlemi tool kullanmadan yapma! Her işlem için uygun tool'u kullan.

DOSYA İŞLEME KURALLARI:
- Kullanıcının yüklediği dosyalar "C:\\mcpler\\education_mcp\\shared_uploads\\" klasöründe bulunur
- Eğer kullanıcı dosya yüklediyse, bu dosyayı işlemek için uygun tool'u kullan:
  * PDF dosyaları için: pdf_ozetle(dosya_adi, ozet_tipi="kapsamli", hedef_dil="Türkçe")
  * Ses dosyaları için: ses_dosyasini_transkript_et(dosya_adi, cikti_tipi="ozet", hedef_dil="Türkçe")
  * Video dosyaları için: videoyu_ozetle(video_dosyasi_yolu=dosya_adi, ozet_tipi="kapsamli", hedef_dil="Türkçe")
- Dosya adını tam yol olarak değil, sadece dosya adı olarak kullan
- Tool çağrısında dosya adını parametre olarak ver
- Dosya yollarını asla kimseye söyleme, sadece toollara gönder
- Kullanıcı "önceki dosyam", "daha önce yüklediğim dosya" gibi ifadeler kullanırsa, o dosyayı anlık olarak işle ve sonra sil
- Dosyalar sadece bir kez kullanılır, sonra otomatik olarak temizlenir

DİĞER İŞLEMLER İÇİN TOOL KULLANIMI:
- Quiz oluşturma için: soru_olustur(konu, soru_sayisi, zorluk, soru_tipi)
- Web araması için: soru_olustur fonksiyonunun web_arama parametresi
- Her işlem için mutlaka uygun tool'u çağır{file_path_info}

KRİTİK KURALLAR: 
- Hiçbir işlemi tool kullanmadan yapma!
- Her dosya işlemi için uygun tool'u kullan
- Her quiz oluşturma için soru_olustur tool'unu kullan
- Tool kullanmadan hiçbir cevap verme
- JSON verisini okunaklı formata çevir
- Sonuç yoksa "Bulunamadı" de
- Türkçe ve anlaşılır cevaplar ver
- Pro sürümde detaylı, kapsamlı ve uzun cevaplar ver
- Örnekler ve açıklamalar ekle
- Adım adım çözümler sun
"""

# --------------------------- Veritabanı İşlemleri ---------------------------
def verify_password(password, password_hash):
    """Şifre doğrulama"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def hash_password(password):
    """Şifre hashleme"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def get_user_by_username(username):
    """Kullanıcı adına göre kullanıcı getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username = %s AND is_active = 1"
            cursor.execute(sql, (username,))
            return cursor.fetchone()
    finally:
        conn.close()

def create_user(username, password, email, full_name):
    """Yeni kullanıcı oluştur"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            password_hash = hash_password(password)
            sql = """INSERT INTO users (username, password_hash, email, full_name, role, plan_type) 
                     VALUES (%s, %s, %s, %s, 'user', 'free')"""
            cursor.execute(sql, (username, password_hash, email, full_name))
            conn.commit()
            return cursor.lastrowid
    finally:
        conn.close()

def update_user_plan(user_id, plan_type):
    """Kullanıcı planını güncelle"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE users SET plan_type = %s WHERE id = %s"
            cursor.execute(sql, (plan_type, user_id))
            conn.commit()
            return True
    except Exception as e:
        print(f"Plan güncelleme hatası: {e}")
        return False
    finally:
        conn.close()

def update_last_login(user_id):
    """Son giriş zamanını güncelle"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE users SET last_login = NOW() WHERE id = %s"
            cursor.execute(sql, (user_id,))
            conn.commit()
    finally:
        conn.close()

def create_chat_session(user_id, session_name="Yeni Chat"):
    """Yeni chat oturumu oluştur"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            session_id = hashlib.md5(f"{user_id}_{time.time()}".encode()).hexdigest()
            sql = """INSERT INTO chat_sessions (user_id, session_id, session_name) 
                     VALUES (%s, %s, %s)"""
            cursor.execute(sql, (user_id, session_id, session_name))
            conn.commit()
            return cursor.lastrowid, session_id
    finally:
        conn.close()

def get_user_chat_sessions(user_id):
    """Kullanıcının chat oturumlarını getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT cs.*, COUNT(cm.id) as message_count 
                     FROM chat_sessions cs 
                     LEFT JOIN chat_messages cm ON cs.session_id = cm.session_id 
                     WHERE cs.user_id = %s AND cs.is_active = 1 
                     GROUP BY cs.id 
                     ORDER BY cs.last_activity DESC"""
            cursor.execute(sql, (user_id,))
            return cursor.fetchall()
    finally:
        conn.close()

def save_chat_message(session_id, user_id, message_type, content, file_path=None):
    """Chat mesajını kaydet (dosya yolu ile birlikte)"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO chat_messages (session_id, user_id, message_type, content, file_path) 
                     VALUES (%s, %s, %s, %s, %s)"""
            cursor.execute(sql, (session_id, user_id, message_type, content, file_path))
            conn.commit()
            return cursor.lastrowid
    finally:
        conn.close()

def get_chat_messages(session_id):
    """Chat mesajlarını getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM chat_messages 
                     WHERE session_id = %s 
                     ORDER BY created_at ASC"""
            cursor.execute(sql, (session_id,))
            return cursor.fetchall()
    finally:
        conn.close()

def get_current_session_file_path(session_id, user_id):
    """Mevcut oturumun son dosya yolunu getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT file_path FROM chat_messages 
            WHERE session_id = %s AND user_id = %s AND file_path IS NOT NULL 
            ORDER BY created_at DESC 
            LIMIT 1
            """
            cursor.execute(sql, (session_id, user_id))
            result = cursor.fetchone()
            return result['file_path'] if result else None
    finally:
        conn.close()

def get_file_info_by_path(file_path):
    """Dosya yoluna göre dosya bilgilerini getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT file_path, file_type FROM uploaded_files 
            WHERE file_path = %s AND is_active = 1
            """
            cursor.execute(sql, (file_path,))
            result = cursor.fetchone()
            return result if result else None
    finally:
        conn.close()

def save_uploaded_file(user_id, filename, original_filename, file_path, file_type, file_size):
    """Yüklenen dosyayı kaydet"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO uploaded_files 
                     (user_id, filename, original_filename, file_path, file_type, file_size) 
                     VALUES (%s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (user_id, filename, original_filename, file_path, file_type, file_size))
            conn.commit()
            return cursor.lastrowid
    finally:
        conn.close()

def get_user_files(user_id):
    """Kullanıcının dosyalarını getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM uploaded_files 
                     WHERE user_id = %s AND is_active = 1 
                     ORDER BY uploaded_at DESC"""
            cursor.execute(sql, (user_id,))
            return cursor.fetchall()
    finally:
        conn.close()

def is_valid_session(session_id, user_id):
    """Session ID'nin geçerli olup olmadığını kontrol et"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT id FROM chat_sessions 
                     WHERE session_id = %s AND user_id = %s AND is_active = 1"""
            cursor.execute(sql, (session_id, user_id))
            return cursor.fetchone() is not None
    finally:
        conn.close()

def get_chat_session_info(session_id):
    """Chat session bilgilerini getir"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM chat_sessions 
                     WHERE session_id = %s AND is_active = 1"""
            cursor.execute(sql, (session_id,))
            return cursor.fetchone()
    finally:
        conn.close()

def update_chat_session_name(session_id, chat_name):
    """Chat session adını güncelle"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE chat_sessions SET session_name = %s WHERE session_id = %s"
            cursor.execute(sql, (chat_name, session_id))
            conn.commit()
            return True
    except Exception as e:
        print(f"Chat adı güncelleme hatası: {e}")
        return False
    finally:
        conn.close()

def delete_chat_session(session_id, user_id):
    """Chat session'ı ve tüm mesajlarını sil"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Önce session'ın bu kullanıcıya ait olduğunu kontrol et
            sql = "SELECT session_id FROM chat_sessions WHERE session_id = %s AND user_id = %s"
            cursor.execute(sql, (session_id, user_id))
            if not cursor.fetchone():
                return False
            
            # Önce mesajları sil
            sql = "DELETE FROM chat_messages WHERE session_id = %s"
            cursor.execute(sql, (session_id,))
            
            # Sonra session'ı sil
            sql = "DELETE FROM chat_sessions WHERE session_id = %s"
            cursor.execute(sql, (session_id,))
            
            conn.commit()
            return True
    except Exception as e:
        print(f"Chat silme hatası: {e}")
        return False
    finally:
        conn.close()

# --------------------------- Ana LLM Çağrısı ---------------------------------
async def ai_chat(messages, system_prompt, plan_type="free", user_id=None, session_id=None):
    """
    Gemini + MCP ile sohbet (Plan bazlı model seçimi)
    """
    try:
        # Her çağrı için yeni MCP istemcisi oluştur
        mcp_client = Client(MCP_URL)
        
        # Plan bazlı model seçimi
        model_name = "gemini-2.5-pro" if plan_type == "pro" else "gemini-1.5-pro"
        
        # Dinamik sistem prompt'u oluştur
        if plan_type == "pro":
            system_prompt = get_system_prompt_pro(user_id, session_id)
        else:
            system_prompt = get_system_prompt_free(user_id, session_id)
        
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

            # 3) Gemini'ye istek gönder (Plan bazlı model)
            response = await gemini.aio.models.generate_content(
                model=model_name,
                contents=content_list,
                config=types.GenerateContentConfig(
                    tools=[mcp_client.session],   # MCP araç listesini ekle
                    max_output_tokens=8192*2,  # Her iki plan için aynı token limiti
                    temperature=0.5,
                )
            )

            # 4) Yanıtı güvenli şekilde al
            if response and hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content') and candidate.content:
                    # Sadece text parts'ları al
                    text_parts = []
                    for part in candidate.content.parts:
                        if hasattr(part, 'text') and part.text:
                            text_parts.append(part.text)
                    
                    if text_parts:
                        content_out = " ".join(text_parts).strip()
                    else:
                        content_out = ""
                else:
                    content_out = ""
            else:
                content_out = ""

            return content_out if content_out else "Üzgünüm, bir yanıt oluşturamadım. Lütfen tekrar deneyin."

    except Exception as e:
        print(f"Hata oluştu: {e}")
        return "Üzgünüm, bir hata oluştu. Lütfen tekrar deneyin."

# --------------------------- Web Routes --------------------------------------
@app.route('/')
def index():
    """Ana sayfa - giriş yapmış kullanıcıları chat'e yönlendir"""
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Giriş sayfası"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            user = get_user_by_username(username)
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['full_name'] = user['full_name']
                session['plan_type'] = user['plan_type']
                session['role'] = user['role']
                
                # Son giriş zamanını güncelle
                update_last_login(user['id'])
                
                flash('Başarıyla giriş yaptınız!', 'success')
                return redirect(url_for('chat'))
            else:
                flash('Kullanıcı adı veya şifre hatalı!', 'error')
        else:
            flash('Kullanıcı adı ve şifre gerekli!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Kayıt sayfası"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name', username)
        
        if username and email and password:
            # Kullanıcı adı kontrolü
            existing_user = get_user_by_username(username)
            if existing_user:
                flash('Bu kullanıcı adı zaten kullanılıyor!', 'error')
            else:
                try:
                    user_id = create_user(username, password, email, full_name)
                    flash('Hesabınız başarıyla oluşturuldu!', 'success')
                    return redirect(url_for('login'))
                except Exception as e:
                    flash('Kayıt sırasında bir hata oluştu!', 'error')
        else:
            flash('Tüm alanları doldurun!', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Çıkış"""
    session.clear()
    flash('Başarıyla çıkış yaptınız!', 'success')
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    """Ana chat sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('chat.html', 
                         username=session.get('username', 'Misafir'),
                         full_name=session.get('full_name', 'Misafir Kullanıcı'),
                         plan_type=session.get('plan_type', 'free'))

@app.route('/chats')
def chats():
    """Chat geçmişi sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    chat_sessions = get_user_chat_sessions(user_id)
    
    return render_template('chats.html',
                         username=session.get('username', 'Misafir'),
                         full_name=session.get('full_name', 'Misafir Kullanıcı'),
                         plan_type=session.get('plan_type', 'free'),
                         chat_sessions=chat_sessions)

@app.route('/pricing')
def pricing():
    """Planlar sayfası"""
    return render_template('pricing.html',
                         username=session.get('username', 'Misafir'),
                         plan_type=session.get('plan_type', 'free'))

@app.route('/payment')
def payment():
    """Ödeme sayfası"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('payment.html',
                         username=session.get('username', 'Misafir'),
                         plan_type=session.get('plan_type', 'free'))

@app.route('/upgrade-to-pro', methods=['POST'])
def upgrade_to_pro():
    """Pro plana yükseltme"""
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekiyor'}), 401
    
    try:
        user_id = session['user_id']
        
        # Kullanıcı planını güncelle
        if update_user_plan(user_id, 'pro'):
            # Session'ı güncelle
            session['plan_type'] = 'pro'
            
            return jsonify({
                'success': True,
                'message': 'Pro plana başarıyla yükseltildiniz!'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Plan yükseltme sırasında bir hata oluştu'
            }), 500
            
    except Exception as e:
        print(f"Plan yükseltme hatası: {e}")
        return jsonify({
            'success': False,
            'error': 'Bir hata oluştu'
        }), 500

# --------------------------- API Routes --------------------------------------
@app.route('/api/chat', methods=['POST'])
async def chat_api():
    """REST API ile sohbet"""
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Oturum açmanız gerekiyor'}), 401
        
        data = request.get_json()
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id')
        
        if not user_message:
            return jsonify({'error': 'Mesaj boş olamaz'}), 400
        
        user_id = session['user_id']
        plan_type = session.get('plan_type', 'free')
        
        # Dosya yolu takibi - kullanıcının son yüklediği dosya varsa al
        current_file_path = None
        if session.get('current_file'):
            current_file_path = session['current_file']['path']
            # Dosya yolunu kullandıktan sonra session'dan temizle
            session.pop('current_file', None)
        
        # Chat oturumu oluştur veya mevcut oturumu kullan
        if not session_id:
            chat_id, session_id = create_chat_session(user_id)
        else:
            # Session ID'nin geçerli olup olmadığını kontrol et
            if not is_valid_session(session_id, user_id):
                return jsonify({'error': 'Geçersiz chat oturumu'}), 400
        
        # Kullanıcı mesajını kaydet (dosya yolu ile birlikte)
        save_chat_message(session_id, user_id, 'user', user_message, current_file_path)
        
        # Önceki mesajları getir
        messages_data = get_chat_messages(session_id)
        messages = []
        for msg in messages_data:
            messages.append({
                "role": msg['message_type'],
                "content": msg['content']
            })
        
        # AI'dan yanıt al
        response = await ai_chat(messages, "", plan_type, user_id, session_id)
        
        if response and response.strip():
            # AI yanıtını kaydet (AI yanıtında dosya yolu yok)
            save_chat_message(session_id, user_id, 'assistant', response, None)
            
            return jsonify({
                'response': response,
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id
            })
        else:
            return jsonify({'error': 'Yanıt alınamadı, lütfen tekrar deneyin'}), 500
            
    except Exception as e:
        print(f"Chat API Hatası: {e}")
        return jsonify({'error': 'Bir hata oluştu'}), 500

@app.route('/api/new-chat', methods=['POST'])
def new_chat():
    """Yeni chat oluştur"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Oturum açmanız gerekiyor'}), 401
        
        data = request.get_json()
        chat_name = data.get('chat_name', 'Yeni Chat').strip()
        
        if not chat_name:
            return jsonify({'success': False, 'error': 'Chat adı gerekli'}), 400
        
        user_id = session['user_id']
        
        # Yeni chat oturumu oluştur
        chat_id, session_id = create_chat_session(user_id, chat_name)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'chat_name': chat_name,
            'message': 'Yeni chat başarıyla oluşturuldu'
        })
        
    except Exception as e:
        print(f"Yeni chat oluşturma hatası: {e}")
        return jsonify({'success': False, 'error': 'Bir hata oluştu'}), 500

@app.route('/api/load-chat')
def load_chat():
    """Chat'i yükle"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Oturum açmanız gerekiyor'}), 401
        
        session_id = request.args.get('session_id')
        user_id = session['user_id']
        
        if not session_id:
            return jsonify({'success': False, 'error': 'Session ID gerekli'}), 400
        
        # Session'ın geçerli olup olmadığını kontrol et
        if not is_valid_session(session_id, user_id):
            return jsonify({'success': False, 'error': 'Geçersiz chat oturumu'}), 400
        
        # Chat bilgilerini getir
        chat_info = get_chat_session_info(session_id)
        if not chat_info:
            return jsonify({'success': False, 'error': 'Chat bulunamadı'}), 404
        
        # Mesajları getir
        messages = get_chat_messages(session_id)
        
        return jsonify({
            'success': True,
            'chat_name': chat_info['session_name'],
            'messages': messages
        })
        
    except Exception as e:
        print(f"Chat yükleme hatası: {e}")
        return jsonify({'success': False, 'error': 'Bir hata oluştu'}), 500

@app.route('/api/update-chat-name', methods=['POST'])
def update_chat_name():
    """Chat adını güncelle"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Oturum açmanız gerekiyor'}), 401
        
        data = request.get_json()
        session_id = data.get('session_id')
        chat_name = data.get('chat_name', '').strip()
        user_id = session['user_id']
        
        if not session_id or not chat_name:
            return jsonify({'success': False, 'error': 'Session ID ve chat adı gerekli'}), 400
        
        # Session'ın geçerli olup olmadığını kontrol et
        if not is_valid_session(session_id, user_id):
            return jsonify({'success': False, 'error': 'Geçersiz chat oturumu'}), 400
        
        # Chat adını güncelle
        if update_chat_session_name(session_id, chat_name):
            return jsonify({
                'success': True,
                'message': 'Chat adı başarıyla güncellendi'
            })
        else:
            return jsonify({'success': False, 'error': 'Chat adı güncellenemedi'}), 500
        
    except Exception as e:
        print(f"Chat adı güncelleme hatası: {e}")
        return jsonify({'success': False, 'error': 'Bir hata oluştu'}), 500

@app.route('/api/clear', methods=['POST'])
def clear_chat():
    """Sohbet geçmişini temizle"""
    session.pop('current_session_id', None)
    return jsonify({'success': True})

@app.route('/upload', methods=['POST'])
def upload_file():
    """Dosya yükleme"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Oturum açmanız gerekiyor'}), 401
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Dosya seçilmedi'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Dosya seçilmedi'}), 400
        
        # Dosya türü kontrolü
        allowed_extensions = {
            'pdf': 'PDF',
            'mp3': 'AUDIO', 'wav': 'AUDIO', 'm4a': 'AUDIO',
            'mp4': 'VIDEO', 'avi': 'VIDEO', 'mov': 'VIDEO', 'mkv': 'VIDEO', 'webm': 'VIDEO',
            'txt': 'TEXT', 'doc': 'DOCUMENT', 'docx': 'DOCUMENT'
        }
        
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if file_extension not in allowed_extensions:
            return jsonify({'success': False, 'error': 'Desteklenmeyen dosya türü'}), 400
        
        file_type = allowed_extensions[file_extension]
        
        # Dosyayı kaydet
        upload_folder = r'C:\mcpler\education_mcp\shared_uploads'
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        # Benzersiz dosya adı oluştur
        import uuid
        unique_filename = f"{uuid.uuid4()}_{file.filename}"
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        
        # Veritabanına kaydet
        user_id = session['user_id']
        file_size = os.path.getsize(file_path)
        file_id = save_uploaded_file(user_id, unique_filename, file.filename, file_path, file_type, file_size)
        
        session['current_file'] = {
            'id': file_id,
            'name': file.filename,
            'type': file_type,
            'path': file_path
        }
        
        return jsonify({
            'success': True,
            'name': file.filename,
            'type': file_type
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/clear-file', methods=['POST'])
def clear_file():
    """Yüklenen dosyayı temizle"""
    session.pop('current_file', None)
    return jsonify({'success': True})

@app.route('/api/delete-chat/<session_id>', methods=['DELETE', 'GET'])
def delete_chat(session_id):
    """Chat'i sil"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Oturum açmanız gerekiyor'}), 401
        
        user_id = session['user_id']
        
        # Chat'i sil
        success = delete_chat_session(session_id, user_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Chat başarıyla silindi'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Chat silinemedi veya bulunamadı'
            }), 404
            
    except Exception as e:
        print(f"Chat silme hatası: {e}")
        return jsonify({'success': False, 'error': 'Bir hata oluştu'}), 500

# --------------------------- WebSocket Events --------------------------------
@socketio.on('connect')
def handle_connect():
    """Kullanıcı bağlandığında"""
    print(f"Kullanıcı bağlandı: {request.sid}")
    emit('status', {'message': 'Eğitim Asistanına hoş geldiniz!'})

@socketio.on('disconnect')
def handle_disconnect():
    """Kullanıcı ayrıldığında"""
    print(f"Kullanıcı ayrıldı: {request.sid}")

@socketio.on('send_message')
async def handle_message(data):
    """WebSocket ile mesaj gönderme"""
    try:
        if 'user_id' not in session:
            emit('error', {'message': 'Oturum açmanız gerekiyor'})
            return
        
        user_message = data.get('message', '').strip()
        session_id = data.get('session_id')
        
        if not user_message:
            emit('error', {'message': 'Mesaj boş olamaz'})
            return
        
        # Dosya yolu takibi - kullanıcının son yüklediği dosya varsa al
        current_file_path = None
        if session.get('current_file'):
            current_file_path = session['current_file']['path']
            print(f"DEBUG: Current file path: {current_file_path}")
            # Dosya yolunu kullandıktan sonra session'dan temizle
            session.pop('current_file', None)
            print("DEBUG: File path cleared from session")
        
        # Kullanıcı mesajını hemen göster
        emit('user_message', {
            'message': user_message,
            'timestamp': datetime.now().isoformat()
        })
        
        user_id = session['user_id']
        plan_type = session.get('plan_type', 'free')
        
        # Chat oturumu oluştur veya mevcut oturumu kullan
        if not session_id:
            chat_id, session_id = create_chat_session(user_id)
        else:
            # Session ID'nin geçerli olup olmadığını kontrol et
            if not is_valid_session(session_id, user_id):
                emit('error', {'message': 'Geçersiz chat oturumu'})
                return
        
        # Kullanıcı mesajını kaydet (dosya yolu ile birlikte)
        save_chat_message(session_id, user_id, 'user', user_message, current_file_path)
        
        # "Yazıyor..." durumu gönder
        emit('typing', {'status': True})
        
        # Tool durumunu belirle ve gönder
        tool_status = determine_tool_status(user_message, current_file_path)
        if tool_status:
            emit('tool_status', tool_status)
        
        # Önceki mesajları getir
        messages_data = get_chat_messages(session_id)
        messages = []
        for msg in messages_data:
            messages.append({
                "role": msg['message_type'],
                "content": msg['content']
            })
        
        # AI'dan yanıt al
        response = await ai_chat(messages, "", plan_type, user_id, session_id)
        
        # "Yazıyor..." durumunu kapat
        emit('typing', {'status': False})
        
        if response and response.strip():
            # AI yanıtını kaydet ve gönder (AI yanıtında dosya yolu yok)
            save_chat_message(session_id, user_id, 'assistant', response, None)
            
            emit('bot_message', {
                'message': response,
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id
            })
        else:
            emit('error', {'message': 'Yanıt alınamadı, lütfen tekrar deneyin'})
            
    except Exception as e:
        print(f"WebSocket Mesaj Hatası: {e}")
        emit('typing', {'status': False})
        emit('error', {'message': 'Bir hata oluştu'})

def determine_tool_status(message, file_path):
    """Mesaj ve dosya yoluna göre hangi tool'un kullanılacağını belirle"""
    message_lower = message.lower()
    
    # Dosya türüne göre tool belirleme
    if file_path:
        file_extension = file_path.lower().split('.')[-1] if '.' in file_path else ''
        
        if file_extension == 'pdf':
            return {
                'tool': 'pdf_summarizer',
                'status': 'PDF özetleniyor...',
                'icon': 'fa-file-pdf'
            }
        elif file_extension in ['mp3', 'wav', 'm4a']:
            return {
                'tool': 'audio_transcriber',
                'status': 'Ses dosyası işleniyor...',
                'icon': 'fa-file-audio'
            }
        elif file_extension in ['mp4', 'avi', 'mov', 'mkv', 'webm']:
            return {
                'tool': 'video_summarizer',
                'status': 'Video özetleniyor...',
                'icon': 'fa-file-video'
            }
    
    # Mesaj içeriğine göre tool belirleme
    if any(word in message_lower for word in ['quiz', 'soru', 'test']):
        return {
            'tool': 'quiz_generator',
            'status': 'Quiz oluşturuluyor...',
            'icon': 'fa-question-circle'
        }
    elif any(word in message_lower for word in ['özet', 'summary']):
        if 'video' in message_lower:
            return {
                'tool': 'video_summarizer',
                'status': 'Video kapsamlı özetleniyor...',
                'icon': 'fa-file-video'
            }
        elif 'pdf' in message_lower or 'doküman' in message_lower:
            return {
                'tool': 'pdf_summarizer',
                'status': 'PDF kapsamlı özetleniyor...',
                'icon': 'fa-file-pdf'
            }
    
    # Varsayılan durum
    return {
        'tool': 'ai_chat',
        'status': 'AI düşünüyor...',
        'icon': 'fa-brain'
    }

@socketio.on('clear_chat')
def handle_clear_chat():
    """Sohbet geçmişini temizle"""
    session.pop('current_session_id', None)
    emit('chat_cleared', {'success': True})

# --------------------------- Uygulama Başlatma -------------------------------
if __name__ == '__main__':
    print("\n" + "="*62)
    print("           G E M I N I   E Ğ İ T İ M   A S İ S T A N I")
    print("                        W E B   A P P")
    print("="*62)
    print("http://localhost:5000 adresinden erişebilirsiniz")
    print("-" * 62)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
