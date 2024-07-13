package homehandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"form-project/datahandlers"
	"form-project/utils"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type User struct {
	ID       int            `validate:"-"`
	Email    string         `validate:"required,email"`
	Username sql.NullString // Google kayıtta bazen boş olabilir
	Password sql.NullString // Google kayıtta şifre alanı gereksiz olabilir
}

type Post struct {
	ID                  int
	UserID              int
	Title               string
	Content             string
	Categories          []string // JSON olarak kaydedilecek ve geri okunacak
	CategoriesFormatted string   // Virgülle ayrılmış kategoriler
	CreatedAt           time.Time
	CreatedAtFormatted  string
	LikeCount           int
	DislikeCount        int
	Username            string
	CommentCount        int
}

type RegisterTemplateData struct {
	ErrorMessages map[string]string
	Email         string
	Username      string
}

var (
	validate = validator.New()
	config   Config
)

type Config struct {
	GoogleClientID       string `json:"google_client_id"`
	GoogleClientSecret   string `json:"google_client_secret"`
	GitHubClientID       string `json:"github_client_id"`
	GitHubClientSecret   string `json:"github_client_secret"`
	FacebookClientID     string `json:"facebook_client_id"`
	FacebookClientSecret string `json:"facebook_client_secret"`
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config file: %s", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode config file: %s", err)
	}
}

var googleOauthConfig *oauth2.Config
var githubOauthConfig *oauth2.Config
var facebookOauthConfig *oauth2.Config

func init() {
	loadConfig()
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/google/callback",
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
	githubOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/github/callback",
		ClientID:     config.GitHubClientID,
		ClientSecret: config.GitHubClientSecret,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
	facebookOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8065/facebook/callback",
		ClientID:     config.FacebookClientID,
		ClientSecret: config.FacebookClientSecret,
		Scopes:       []string{"public_profile", "email"},
		Endpoint:     facebook.Endpoint,
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) { // `HomeHandler` fonksiyonu, ana sayfa isteğini işler ve gerekli verileri hazırlayarak
	// şablonu oluşturur ve istemciye geri döner.
	session, _ := datahandlers.GetSession(r) // İstekten oturum bilgisini alır. Oturum bilgisi kullanıcı giriş yapmış mı belirler.

	searchQuery := r.URL.Query().Get("search") // URL'deki `search` parametresini alır. Bu, arama sorgusunu temsil eder.
	category := r.URL.Query().Get("category")  // URL'deki `category` parametresini alır. Bu, filtrelenecek kategoriyi temsil eder.
	filter := r.URL.Query().Get("filter")      // URL'deki `filter` parametresini alır. Bu, ek filtreleri temsil eder.

	posts, err := getFilteredPosts(searchQuery, category, filter, nil)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	} //// `getFilteredPosts` fonksiyonunu çağırarak arama sorgusuna, kategoriye ve filtrelere
	// göre filtrelenmiş gönderileri alır. Hata olursa `err` değişkenine atar.

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Posts    []Post
		LoggedIn bool
	}{
		Posts:    posts,
		LoggedIn: session != nil,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func getFilteredPosts(searchQuery, category, filter string, userID *int) ([]Post, error) {
	// `getFilteredPosts` fonksiyonu, verilen arama sorgusu, kategori ve filtreye göre
	// gönderileri veritabanından alır ve döner.
	query := `SELECT posts.id, posts.user_id, posts.title, posts.content, posts.categories, posts.created_at, users.username,
                     COALESCE(SUM(CASE WHEN votes.vote_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
                     COALESCE(SUM(CASE WHEN votes.vote_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count,
                     (SELECT COUNT(*) FROM comments WHERE comments.post_id = posts.id AND comments.deleted = 0) AS comment_count
              FROM posts
              JOIN users ON posts.user_id = users.id
              LEFT JOIN votes ON votes.post_id = posts.id
              WHERE posts.deleted = 0`
	//// SQL sorgusunun temel yapısını tanımlar. Bu sorgu, gönderileri, kullanıcı adlarını,
	// beğeni ve yorum sayılarını alır.

	args := []interface{}{}  // Sorgu parametreleri için
	conditions := []string{} // Filtreleme koşulları için

	if searchQuery != "" {
		conditions = append(conditions, "(posts.title LIKE ? OR posts.content LIKE ?)")
		//// Arama sorgusu boş değilse, başlık veya içerikte arama terimi geçen gönderileri
		// ekler.
		searchTerm := "%" + searchQuery + "%"
		args = append(args, searchTerm, searchTerm)
		//// Arama terimini SQL sorgusu parametrelerine ekler.
	}

	if category != "" {
		conditions = append(conditions, "posts.categories LIKE ?")
		//	// Kategori boş değilse, gönderi kategorilerinde kategori terimi geçen gönderileri
		// ekler.
		categoryTerm := "%" + category + "%"
		args = append(args, categoryTerm)
		// Kategori terimini SQL sorgusu parametrelerine ekler.
	}

	if userID != nil {
		conditions = append(conditions, "(posts.user_id = ? OR posts.id IN (SELECT post_id FROM likes WHERE user_id = ?))")
		//// `userID` boş değilse, kullanıcının gönderilerini veya beğendiği gönderileri
		// ekler.
		args = append(args, *userID, *userID)
		//// Kullanıcı ID'sini SQL sorgusu parametrelerine ekler.
	}

	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
		// Eğer herhangi bir koşul eklenmişse, koşulları SQL sorgusuna ekler.
	}

	query += " GROUP BY posts.id"
	// Gönderi ID'sine göre gruplar.

	switch filter {
	case "most_liked":
		query += " ORDER BY like_count DESC"
	// `most_liked` filtresi seçilmişse, beğeni sayısına göre azalan sırada sıralar.
	case "most_commented":
		query += " ORDER BY comment_count DESC"
	// `most_commented` filtresi seçilmişse, yorum sayısına göre azalan sırada sıralar.

	default:
		query += " ORDER BY posts.created_at DESC"
		// Varsayılan olarak, oluşturulma tarihine göre azalan sırada sıralar.
	}

	rows, err := datahandlers.DB.Query(query, args...)
	// SQL sorgusunu çalıştırır ve sonuçları `rows` değişkenine atar.
	if err != nil {
		return nil, err
		// Eğer sorguyu çalıştırırken bir hata oluşursa, hatayı döner.
	}
	defer rows.Close()

	var posts []Post  // Gönderileri saklayacak bir dizi tanımlar.
	for rows.Next() { // Sonuç satırlarını döngü ile okur.

		var post Post
		var categoriesJSON string
		if err := rows.Scan(&post.ID, &post.UserID, &post.Title, &post.Content, &categoriesJSON, &post.CreatedAt, &post.Username, &post.LikeCount, &post.DislikeCount, &post.CommentCount); err != nil {
			return nil, err // Eğer satırı okurken bir hata oluşursa, hatayı döner.

		}
		if err := json.Unmarshal([]byte(categoriesJSON), &post.Categories); err != nil {
			return nil, err
		} // `categoriesJSON`'i JSON'dan diziye dönüştürürken bir hata oluşursa, hatayı döner

		post.CategoriesFormatted = strings.Join(post.Categories, ", ")      // Kategorileri virgülle ayrılmış bir string olarak formatlar.
		post.CreatedAtFormatted = post.CreatedAt.Format("2006-01-02 15:04") // Oluşturulma tarihini belirli bir formatta stringe çevirir.
		posts = append(posts, post)                                         // Gönderiyi `posts` dizisine ekler.

	}
	return posts, nil
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
	if err == nil && session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodPost:
		email := r.FormValue("email")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		googleOAuth := r.FormValue("google_oauth") // Check if Google OAuth info is present

		var user User

		if googleOAuth == "true" {
			// Handle Google OAuth registration
			code := r.FormValue("code")
			token, err := googleOauthConfig.Exchange(r.Context(), code)
			if err != nil {
				http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
				return
			}

			email, name, err := getEmailAndNameFromGoogle(token)
			if err != nil {
				http.Error(w, "Failed to get user info from Google", http.StatusInternalServerError)
				return
			}

			// Generate a username based on Google name
			username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5)

			// Insert or retrieve user ID
			userID, err := getOrCreateUser(email, username)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to save user info: %v", err), http.StatusInternalServerError)
				return
			}

			sessionToken, err := createSession(userID)
			if err != nil {
				http.Error(w, "Failed to create session", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    sessionToken,
				Path:     "/",
				HttpOnly: true,
			})

			http.Redirect(w, r, "/myprofil", http.StatusSeeOther)
			return
		}

		// Handle traditional registration
		username := r.FormValue("username")

		user = User{
			Email:    email,
			Username: sql.NullString{String: username, Valid: true}, // Google kaydında null olmayacak
			Password: sql.NullString{String: password, Valid: true}, // Google kaydında null olmayacak
		}

		err := validate.Struct(user)
		if err != nil {
			errorMessages := make(map[string]string)
			for _, err := range err.(validator.ValidationErrors) {
				field := err.Field()
				switch field {
				case "Username":
					errorMessages[field] = "Username must be alphanumeric and between 3 and 20 characters long."
				case "Password":
					errorMessages[field] = "Password must be at least 6 characters long."
				case "Email":
					errorMessages[field] = "Invalid email format."
				default:
					errorMessages[field] = fmt.Sprintf("Validation error for '%s' failed on the '%s' tag", field, err.Tag())
				}
			}
			renderRegisterTemplate(w, RegisterTemplateData{
				ErrorMessages: errorMessages,
				Email:         user.Email,
				Username:      user.Username.String,
			})
			return
		}

		if password != confirmPassword {
			errorMessages := map[string]string{"ConfirmPassword": "Password and confirm password do not match."}
			renderRegisterTemplate(w, RegisterTemplateData{
				ErrorMessages: errorMessages,
				Email:         user.Email,
				Username:      user.Username.String,
			})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = datahandlers.DB.Exec("INSERT INTO users (email, username, password) VALUES (?, ?, ?)", user.Email, user.Username.String, hashedPassword)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				utils.HandleErr(w, err, "Email or username already taken", http.StatusBadRequest)
			} else {
				utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return

	default: // GET request
		renderRegisterTemplate(w, RegisterTemplateData{})
	}
}

func renderRegisterTemplate(w http.ResponseWriter, data RegisterTemplateData) {
	tmpl, err := template.ParseFiles("templates/register.html") // // Bu satır, templates/register.html dosyasını okur ve
	// bu dosyayı bir template olarak ayrıştırır (parse eder). Hata oluşursa, err değişkenine atanır.
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data) // Template'i belirtilen veri ile birlikte çalıştırır
	//ve sonuç HTML çıktısını ResponseWriter'a (w) yazar. Hata oluşursa, err değişkenine atanır.
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	session, err := datahandlers.GetSession(r)
	if err == nil && session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		var id int
		var hashedPassword string
		err := datahandlers.DB.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&id, &hashedPassword)
		if err != nil {
			utils.HandleErr(w, err, "Invalid email", http.StatusUnauthorized)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			utils.HandleErr(w, err, "Invalid password", http.StatusUnauthorized)
			return
		}

		sessionToken := uuid.New().String()
		expiresAt := time.Now().Add(10 * time.Minute)

		_, err = datahandlers.DB.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionToken, id, expiresAt)
		if err != nil {
			utils.HandleErr(w, err, "Session creation failed", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   true, // Ensure this is set when using HTTPS
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	// İstekten "session_token" adında bir çerez (cookie) almayı dener. Eğer hata oluşursa, hata 'err' değişkenine atanır.
	if err != nil { // Eğer çerezi alırken bir hata oluşursa, bu blok çalışır.
		if err == http.ErrNoCookie { // Hata, çerezin mevcut olmadığını belirtiyorsa (http.ErrNoCookie),
			http.Redirect(w, r, "/", http.StatusSeeOther) //Kullanıcıyı ana sayfaya ("/") 303 (See Other) durum kodu ile yönlendirir.
			return
		}
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError) // Başka bir hata oluştuysa, hata işleme fonksiyonu çağrılır.
		//Kullanıcıya "Internal server error" mesajı ve 500 (Internal Server Error) durumu gönderilir.
		return // Fonksiyonun geri kalanının çalışmasını durdurmak için return ifadesi kullanılır.
	}

	sessionToken := cookie.Value                                                     // Çerezin değerini 'sessionToken' değişkenine atar.
	_, err = datahandlers.DB.Exec("DELETE FROM sessions WHERE id = ?", sessionToken) // Veritabanındaki 'sessions' tablosundan 'sessionToken' değeri ile eşleşen oturumu siler.
	//Eğer Hata oluşursa, hata 'err' değişkenine atanır.
	if err != nil { // Eğer oturumu silerken bir hata oluşursa, bu blok çalışır.
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		// Hata işleme fonksiyonu çağrılır. Kullanıcıya "Internal server error" mesajı ve 500 (Internal Server Error) durumu gönderilir.
		return // Fonksiyonun geri kalanının çalışmasını durdurmak için return ifadesi kullanılır.
	}

	http.SetCookie(w, &http.Cookie{ // Kullanıcının tarayıcısındaki "session_token" çerezini boş bir değer ve geçmiş bir tarih ile ayarlayarak çerezi geçersiz kılar.
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Second), // Çerezin geçerlilik süresi geçmiş bir tarih olarak ayarlanır.
	})

	http.Redirect(w, r, "/", http.StatusSeeOther) // Kullanıcıyı ana sayfaya ("/") 303 (See Other) durum kodu ile yönlendirir.
}
func HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	url := githubOauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	//"code" burada github geri çağrı (callback) isteği üzerinden gelen
	// erişim kodunu alır.
	token, err := githubOauthConfig.Exchange(r.Context(), code)
	// erişim kodunu kullanarak github'dan erişim token'ı alma.
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	email, name, err := getEmailAndNameFromGitHub(token) //kullanıcı bilgileri alma
	if err != nil {
		http.Error(w, "Failed to get user info from GitHub", http.StatusInternalServerError)
		return
	}

	username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5)

	userID, err := getOrCreateUser(email, username)
	//veritabanında kullanıcı oluşturur veya varsa kullanıcı bilgilerini getirir.
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save user info: %v", err), http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(userID)
	//kullanıcı için oturum token'i oluşturur ve döndürür.
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		//kullanıcıya oturum token'ini tarayıcı üzerinden çerez olarak gönderir.
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "/myprofil", http.StatusTemporaryRedirect)
}

func getEmailAndNameFromGitHub(token *oauth2.Token) (string, string, error) {
	client := githubOauthConfig.Client(oauth2.NoContext, token)
	resp, err := client.Get("https://api.github.com/user")
	//github/user endpoint'ine GET isteği gönderir, kullanıcı bilgilerini alır.
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	if userInfo.Email == "" {
		emailResp, err := client.Get("https://api.github.com/user/emails")
		// GitHub email adresini ayrı bir endpoint'den almak gerekiyor.
		if err != nil {
			return "", "", err
		}
		defer emailResp.Body.Close()

		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
			return "", "", err
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				userInfo.Email = e.Email
				break
			}
		}
	}

	return userInfo.Email, userInfo.Name, nil
}

func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	// Google OAuth2 yapılandırmasından oturum açma için URL oluşturulur.
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	// Google tarafından sağlanan erişim kodunu alır.
	token, err := googleOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	email, name, err := getEmailAndNameFromGoogle(token)
	if err != nil {
		http.Error(w, "Failed to get user info from Google", http.StatusInternalServerError)
		return
	}

	// Validate işlemi yapmadan önce gelen ismi uygun hale getirme
	username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5) // Boşlukları kaldırma gibi bir işlem yapabilirsiniz

	userID, err := getOrCreateUser(email, username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save user info: %v", err), http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(userID)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{ //kullanıcı için oturum token'i oluşturma
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "/myprofil", http.StatusTemporaryRedirect)
}

func HandleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	url := facebookOauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := facebookOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("Token exchange error: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	email, name, err := getEmailAndNameFromFacebook(token)
	if err != nil {
		log.Printf("User info retrieval error: %v", err)
		http.Error(w, "Failed to get user info from Facebook", http.StatusInternalServerError)
		return
	}

	username := strings.ToLower(strings.ReplaceAll(name, " ", "")) + "_" + generateRandomString(5)

	userID, err := getOrCreateUser(email, username)
	if err != nil {
		log.Printf("Failed to save user info: %v", err)
		http.Error(w, fmt.Sprintf("Failed to save user info: %v", err), http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(userID)
	if err != nil {
		log.Printf("Failed to create session: %s", err)
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
	})

	http.Redirect(w, r, "/myprofil", http.StatusTemporaryRedirect)
}

func getEmailAndNameFromFacebook(token *oauth2.Token) (string, string, error) {
	client := facebookOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://graph.facebook.com/me?fields=email,name")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	return userInfo.Email, userInfo.Name, nil
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func getEmailAndNameFromGoogle(token *oauth2.Token) (string, string, error) {
	client := googleOauthConfig.Client(oauth2.NoContext, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	// userinfo endpoint'ine GET isteği gönderilerek kullanıcı bilgileri alınır.
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", "", err
	}

	return userInfo.Email, userInfo.Name, nil
}

func getOrCreateUser(email, username string) (int64, error) {
	var userID int64
	err := datahandlers.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	// Veritabanında verilen e-postaya sahip bir kullanıcı arar ve kullanıcı ID'sini userID'ye atar.
	if err == sql.ErrNoRows {
		// Eğer kullanıcı bulunamazsa (satır yoksa), yeni bir kullanıcı oluşturur.
		res, err := datahandlers.DB.Exec("INSERT INTO users (email, username) VALUES (?, ?)", email, username)
		// Yeni kullanıcıyı veritabanına ekler.

		if err != nil {
			return 0, err // Bir hata oluşursa hatayı döner.

		}
		userID, err = res.LastInsertId() // Yeni oluşturulan kullanıcının ID'sini alır.
		if err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	return userID, nil
}

func createSession(userID int64) (string, error) {
	sessionToken := fmt.Sprintf("session-%d-%d", userID, time.Now().UnixNano())
	// Benzersiz bir oturum belirteci oluşturur. Bu, kullanıcı ID'si ve mevcut zaman damgasını içerir.
	expiry := time.Now().Add(10 * time.Minute) // Oturum süresini 10 dakika sonrasına ayarlar.
	_, err := datahandlers.DB.Exec("INSERT INTO sessions (id, user_id, expiry) VALUES (?, ?, ?)", sessionToken, userID, expiry)
	// Oturumu veritabanına ekler.
	if err != nil {
		return "", err
	}
	return sessionToken, nil
}

func SifreUnutHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/sifreunut.html")
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		utils.HandleErr(w, err, "Internal server error", http.StatusInternalServerError)
	}
}
