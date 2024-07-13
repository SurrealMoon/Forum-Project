package allhandlers // Bu paket, tüm HTTP istek işleyicilerini (handler) merkezi bir yerde toplar.

import ( // Gerekli paketler import edilir.
	"form-project/homehandlers" // Ana sayfa ve oturum işlemleriyle ilgili işleyiciler.
	"form-project/morehandlers" // Diğer özel işlevler için işleyiciler.
	"form-project/posthandlers" // Gönderi (post) işlemleri için işleyiciler.
	"net/http"                  // HTTP sunucu ve istek/cevap yönetimi için standart Go paketi.
	"strings"                   // String (karakter dizisi) işleme fonksiyonları.
)

func Allhandlers() { // Bu fonksiyon, tüm istek işleyicilerini kaydeder.
	// Statik Dosya Sunumu:
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) { // "/static/" ile başlayan istekler için statik dosya sunar.
		path := r.URL.Path[1:]                   // İstek yolundan ilk "/" karakterini kaldırır.
		if !strings.HasPrefix(path, "static/") { // Yol "static/" ile başlamazsa...
			http.NotFound(w, r) // 404 Not Found yanıtı gönderir.
			return              // Fonksiyondan çıkar.
		}
		http.ServeFile(w, r, path) // Statik dosyayı sunar.
	})

	// Google Oturum İşlemleri:
	http.HandleFunc("/google/login", homehandlers.HandleGoogleLogin)       // Google ile oturum açma işlemi için işleyici.
	http.HandleFunc("/google/callback", homehandlers.HandleGoogleCallback) // Google'dan dönen callback isteği için işleyici.

	// GitHub Oturum İşlemleri:
	http.HandleFunc("/github/login", homehandlers.HandleGitHubLogin)       // GitHub ile oturum açma işlemi için işleyici.
	http.HandleFunc("/github/callback", homehandlers.HandleGitHubCallback) // GitHub'dan dönen callback isteği için işleyici.
	// Facebook Oturum İşlemleri:
	http.HandleFunc("/facebook/login", homehandlers.HandleFacebookLogin)
	http.HandleFunc("/facebook/callback", homehandlers.HandleFacebookCallback)

	// Diğer İşleyiciler:
	http.HandleFunc("/", homehandlers.HomeHandler)               // Ana sayfa için işleyici.
	http.HandleFunc("/register", homehandlers.RegisterHandler)   // Kayıt olma sayfası için işleyici.
	http.HandleFunc("/login", homehandlers.LoginHandler)         // Oturum açma sayfası için işleyici.
	http.HandleFunc("/logout", homehandlers.LogoutHandler)       // Oturum kapatma işlemi için işleyici.
	http.HandleFunc("/sifreunut", homehandlers.SifreUnutHandler) // Şifre sıfırlama işlemi için işleyici.

	// Gönderi İşlemleri:
	http.HandleFunc("/createPost", posthandlers.CreatePostHandler)       // Gönderi oluşturma işlemi için işleyici.
	http.HandleFunc("/createComment", posthandlers.CreateCommentHandler) // Yorum oluşturma işlemi için işleyici.
	http.HandleFunc("/deletePost", posthandlers.DeletePostHandler)       // Gönderi silme işlemi için işleyici.
	http.HandleFunc("/deleteComment", posthandlers.DeleteCommentHandler) // Yorum silme işlemi için işleyici.
	http.HandleFunc("/vote", posthandlers.VoteHandler)                   // Oy verme işlemi için işleyici.
	http.HandleFunc("/viewPost", posthandlers.ViewPostHandler)           // Gönderiyi görüntüleme işlemi için işleyici.

	// Profil İşlemleri:
	http.HandleFunc("/myprofil", morehandlers.MyProfileHandler) // Kullanıcının profilini görüntüleme işlemi için işleyici.
}

// HTTP (handle) yönlendirmeleri:
// http.HandleFunc("/login", loginHandler)
//çeşitli url yolları için HTTP yönlendirmeleri tanımlar, her bir URL yolu belirli bir HTTP işleyici fonksiyonuna yani "handler"a
// yönlendirilir. Örneğin "/login" yolu "loginHandler" fonksiyonuna yönlendilir. Bu fonksiyonlar HTTP isteklerine yanıt verir.

// homeHandler:
//Bu fonksiyon ana sayfa için gelen HTTP isteklerini işler ve ilgili veriyi veritabanından çekerek "html" şablonuna render eder.

// session,_ := getSession(r)
// gelen isteğin ("r") oturum bilgilerini alır. getsession oturum bilgilerini çeker ve bilgileri session içinde döner.

//SQL Sorgusu Tanımlama:
// homeHandler içinde kullanılan query(sorgu)'nun kullanım amacı 'post' tablosundan gönderileri 'users' tablosundan kullanıcı isimlerini
// ve oyların çekilmesini sağlar. Kısacası post atan kullanıcının verilerini çekmek için kullanılan kısım.
//Bu tür bir sorgu genel olarak blog ve forum sitelerinde kullanılır.

//Docker, uygulamaların ve onların bağımlılıklarının her yerde aynı şekilde çalışmasını sağlayarak geliştirme, test ve üretim ortamlarında
//tutarlılığı sağlar. Docker Image'ları kullanarak konteynerler oluşturur ve bu konteynerler izole edilmiş ortamlarda çalışır.
//Docker'ın sunduğu ağ ve depolama çözümleri, konteynerlerin güvenli ve esnek bir şekilde iletişim kurmasını ve veri saklamasını sağlar.

//Struct'lar, birbirleriyle ilişkili farklı türdeki verileri bir araya getiren ve tek bir birim olarak ele alan veri yapılarıdır.
// verileri anlamlı bir şekilde organize etmeye ve ilgili fonksiyonlarla birlikte çalışmaya olanak tanır.
