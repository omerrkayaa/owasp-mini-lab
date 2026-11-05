# owasp-mini-lab

Küçük bir Flask uygulamasıyla dört yaygın web açığını uçtan uca gösteren bir laboratuvar. Aynı uygulama iki modda çalışır:

- **vulnerable**: açıklar bilerek bırakılmıştır.
- **secure**: aynı uç noktalar, açıklar kapatılmış hâlde.

Her açık için bir saldırı betiği var. Betik açıklı modda başarılı olur, güvenli modda başarısız olur. Testler de bunu doğrular. Böylece açığı ve düzeltmesini aynı dosyada yan yana görebilirsiniz.

> [!WARNING]
> **Bu uygulama kasıtlı olarak açıklıdır. İnternete ya da paylaşılan bir ağa açmayın.**
> Sunucu yalnız `127.0.0.1` üzerinde dinler, saldırı betikleri de yalnız yerel adreslere istek atar (`exploits/common.py` içindeki `ALLOWED_HOSTS`). Bu sınırları kaldırmayın. Betikleri size ait olmayan sistemlerde kullanmayın.

## Kurulum

Python 3.10 ya da üstü gerekir.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Çalıştırma

Uygulamayı başlatın (varsayılan port 5000):

```bash
python -m lab --mode vulnerable
python -m lab --mode secure
```

Başka bir terminalde tüm saldırıları çalıştırın:

```bash
python -m exploits.run_all --url http://127.0.0.1:5000
```

Tek bir saldırıyı da çalıştırabilirsiniz: `python -m exploits.sqli`, `exploits.xss`, `exploits.idor`, `exploits.brute_force`.

Beklenen çıktı:

| Mod | Sonuç |
|---|---|
| vulnerable | `4/4 saldırı başarılı.` |
| secure | `0/4 saldırı başarılı.` |

Testler (sunucu başlatmaya gerek yok, Flask test istemcisi kullanılır):

```bash
pytest
```

Örnek kullanıcılar: `alice / sunshine`, `bob / bob123`. `admin` parolası her açılışta rastgele üretilir.

Veritabanı bellekte (`:memory:`) tutulur, uygulama her açıldığında sıfırlanır.

## Açıklar

Aşağıdaki satır numaraları `lab/__init__.py` dosyasına aittir.

### 1. SQL injection

**Nedir:** Kullanıcı girdisi SQL sorgusuna metin olarak yapıştırılınca girdi, sorgunun yapısını değiştirebilir.

**Nasıl sömürülür:** Kullanıcı adı alanına `admin' --` yazılır. Sorgu şuna dönüşür:

```sql
SELECT id, username FROM users WHERE username = 'admin' --' AND password = '...'
```

`--` sonrası yorum sayılır, parola koşulu hiç çalışmaz ve saldırgan parolayı bilmeden admin olarak girer. Betik: `exploits/sqli.py`.

**Açıklı kod:** satır 105, f-string ile kurulan sorgu. Satır 109'da veritabanı hata mesajı da kullanıcıya gösteriliyor; bu, saldırganın sorguyu deneme yanılmayla çözmesini kolaylaştırır.

**Düzeltme:** satır 96, parametreli sorgu (`WHERE username = ?`). Girdi SQL'in parçası olmaz, yalnız değer olarak gider. Parola sorguda karşılaştırılmaz; satır 97'de `check_password_hash` ile hash'e karşı doğrulanır. Parolalar satır 183'te hash'lenerek saklanır (açıklı modda düz metin).

**OWASP Top 10 (2021):** A03 Injection.

### 2. Stored XSS

**Nedir:** Kullanıcının kaydettiği içerik başka kullanıcılara HTML olarak gösterilince, içine konan betik onların tarayıcısında çalışır.

**Nasıl sömürülür:** bob panoya `<script>document.title='XSS'</script>` yazar. Panoyu açan herkesin sayfasına betik ham hâliyle basılır. Gerçek bir saldırıda betik oturum çerezini çalabilir ya da kurban adına işlem yapabilir. Betik: `exploits/xss.py`.

**Açıklı kod:** satır 165, mesajlar f-string ile HTML'e ekleniyor.

**Düzeltme:** satır 160–162, Jinja2 şablonu otomatik kaçış uygular; `<script>` metin olarak görünür, çalışmaz. İkinci savunma hattı olarak satır 66'da `Content-Security-Policy` başlığı satır içi betikleri engeller. Satır 43'te oturum çerezi `HttpOnly` yapılır, böylece betik çerezi okuyamaz.

**OWASP Top 10 (2021):** A03 Injection (XSS 2021 sürümünde Injection altına alındı).

### 3. IDOR (Insecure Direct Object Reference)

**Nedir:** Uygulama bir nesneyi kullanıcının verdiği kimlikle getirir ama o nesnenin kullanıcıya ait olup olmadığını denetlemez.

**Nasıl sömürülür:** bob kendi hesabıyla girer ve `/notes/1`, `/notes/2` ... adreslerini sırayla dener. Admin'in ve alice'in notlarını okur. Betik: `exploits/idor.py`.

**Açıklı kod:** satır 145, sorgu yalnız `id` ile yapılıyor; giriş yapılmış olması yetiyor.

**Düzeltme:** satır 140–142, sorguya `AND owner_id = ?` eklenir. Başkasının notu 404 döner; böylece notun var olup olmadığı da sızmaz (403 dönseydi "bu numarada bir not var" bilgisi verilmiş olurdu).

**OWASP Top 10 (2021):** A01 Broken Access Control.

### 4. Kaba kuvvet (brute force)

**Nedir:** Giriş denemelerine sınır konmayınca saldırgan bir parola listesini sonuna kadar dener.

**Nasıl sömürülür:** 15 yaygın paroladan oluşan bir liste alice için sırayla denenir; `sunshine` 15. denemede bulunur. Betik: `exploits/brute_force.py`.

**Açıklı kod:** satır 112, deneme sayısı hiç tutulmuyor.

**Düzeltme:** satır 91–93 ve 98–102. Kullanıcı adı başına hatalı deneme sayılır; 5 hatadan sonra hesap 15 dakika kilitlenir ve `429` döner (sınırlar satır 20–21'de). Doğru parola listede olsa bile 6. denemeye gelinmez.

**OWASP Top 10 (2021):** A07 Identification and Authentication Failures.

**Bilinen sınırlar:** Sayaç bellekte tutulur, uygulama yeniden başlayınca sıfırlanır ve birden çok süreç arasında paylaşılmaz. Kullanıcı adına göre kilitlemek, saldırganın başkasının hesabını bilerek kilitlemesine de imkân verir. Gerçek bir sistemde IP tabanlı hız sınırı, artan bekleme süresi ya da CAPTCHA gibi önlemlerle birlikte kullanılmalıdır.

## Proje yapısı

```
lab/__init__.py        uygulama: create_app(secure, db_path), iki mod yan yana
lab/__main__.py        python -m lab --mode vulnerable|secure (yalnız 127.0.0.1)
exploits/common.py     yalnız localhost'a izin veren istemci, login(), report()
exploits/*.py          her açık için bir saldırı betiği; run(client) -> bool
tests/test_exploits.py her saldırı açıklı modda True, güvenli modda False dönmeli
```

## Lisans

MIT. Ayrıntı için [LICENSE](LICENSE).
