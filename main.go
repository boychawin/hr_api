// main.go

package main

import (
	"context"
	"encoding/json"
	"fmt"

	// "hr-api/handlers"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var signingKey = []byte("secret-key")

func main() {

	// 1.ให้ทำ Api ระบบ hr โดยสามารถ เพิ่ม ลบ แก้ไข ดู ข้อมูลพนักงาน
	r := mux.NewRouter()

	employeeHandler := NewEmployeeHandler()

	r.HandleFunc("/api/login", employeeHandler.Login).Methods("POST")
	r.HandleFunc("/api/employees", employeeHandler.AddEmployee).Methods("POST")
	r.HandleFunc("/api/employees", employeeHandler.ViewEmployees).Methods("GET")
	r.HandleFunc("/api/employees/{id}", employeeHandler.GetEmployee).Methods("GET")
	r.HandleFunc("/api/employees/{id}", employeeHandler.EditEmployee).Methods("PUT")
	r.HandleFunc("/api/employees/{id}", employeeHandler.DeleteEmployee).Methods("DELETE")

	// Enable CORS
	corsHandler := cors.Default().Handler(r)

	// Wrap the router with JWT authentication middleware
	authenticatedRouter := authenticateMiddleware(corsHandler)


	// 2. ทำฟังชั่นรับ parameter 2 ตัว เป็น array ทั้งคู่ โดนรีเทินค่า 2 ค่า
	array1 := []string{"a", "b", "c"}
	array2 := []string{"b", "c", "d"}

	concatenated, received := concatenateArrays(array1, array2)
	fmt.Println("value1:", concatenated)
	fmt.Println("value2:", received)



	log.Println("Server started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", authenticatedRouter))


}

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the authorization token from the request header
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse the JWT token
		token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
			// Verify the signing method and key
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("invalid signing method")
			}
			return signingKey, nil
		})

		if err != nil {
			fmt.Println(err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate the token and extract the claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Check if the user is an admin
			if role, ok := claims["role"].(string); ok && role == "admin" {
				// Pass the request to the next handler
				next.ServeHTTP(w, r)
				return
			}
			fmt.Println(claims)
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func (h *EmployeeHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Validate the user credentials
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Check the credentials against the database or any other validation logic
	valid := validateUserCredentials(h, username, password)
	if !valid {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate the JWT token and refresh token
	token, refreshToken, err := generateTokenPair(username)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Send the token and refresh token in the response
	response := map[string]string{
		"token":         token,
		"refresh_token": refreshToken,
	}
	json.NewEncoder(w).Encode(response)
}

func validateUserCredentials(h *EmployeeHandler, username string, password string) bool {

	collection := h.client.Database("hr").Collection("employees")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Query the user by username and password
	filter := bson.M{"username": username, "password": password}
	var result bson.M
	err := collection.FindOne(ctx, filter).Decode(&result)

	fmt.Println(username)
	fmt.Println(result)

	if err != nil {
		return false
	}

	// If a document is found, the credentials are valid
	return true
}

func generateTokenPair(username string) (string, string, error) {
	// Generate the access token
	accessToken, err := generateAccessToken(username)
	if err != nil {
		return "", "", err
	}

	// Generate the refresh token
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func generateAccessToken(username string) (string, error) {
	// Create the claims for the access token
	claims := jwt.MapClaims{
		"username": username,
		"role":     "admin",
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Set expiration time to 24 hours
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	accessToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func generateRefreshToken() (string, error) {
	// Generate a unique refresh token using UUID
	refreshToken := uuid.New().String()
	return refreshToken, nil
}

// Employee represents an employee in the HR system
type Employee struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

type Login struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// EmployeeHandler handles employee-related requests
type EmployeeHandler struct {
	client *mongo.Client
}

// NewEmployeeHandler creates a new instance of EmployeeHandler
func NewEmployeeHandler() *EmployeeHandler {
	// Connect to MongoDB
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	return &EmployeeHandler{
		client: client,
	}
}

// AddEmployee adds a new employee to the HR system
func (h *EmployeeHandler) AddEmployee(w http.ResponseWriter, r *http.Request) {
	var employee Employee
	if err := json.NewDecoder(r.Body).Decode(&employee); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Generate a unique ID for the employee
	employee.ID = uuid.New().String()

	collection := h.client.Database("hr").Collection("employees")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Insert the employee into the database
	_, err := collection.InsertOne(ctx, employee)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the created employee as the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(employee)
}

// ViewEmployees retrieves all employees from the HR system
func (h *EmployeeHandler) ViewEmployees(w http.ResponseWriter, r *http.Request) {
	collection := h.client.Database("hr").Collection("employees")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query all employees
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var employees []Employee
	for cursor.Next(ctx) {
		var employee Employee
		if err := cursor.Decode(&employee); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		employees = append(employees, employee)
	}

	if err := cursor.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert employees to JSON and send the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(employees)
}

// GetEmployee retrieves a specific employee from the HR system
func (h *EmployeeHandler) GetEmployee(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	employeeID := params["id"]

	collection := h.client.Database("hr").Collection("employees")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query the employee by ID
	var employee Employee
	err := collection.FindOne(ctx, bson.M{"id": employeeID}).Decode(&employee)
	if err != nil {
		http.Error(w, "Employee not found", http.StatusNotFound)
		return
	}

	// Convert employee to JSON and send the response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(employee)
}

// EditEmployee updates an existing employee in the HR system
func (h *EmployeeHandler) EditEmployee(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	employeeID := params["id"]

	var updatedEmployee Employee
	if err := json.NewDecoder(r.Body).Decode(&updatedEmployee); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	collection := h.client.Database("hr").Collection("employees")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Update the employee by ID
	result, err := collection.UpdateOne(ctx, bson.M{"id": employeeID}, bson.M{"$set": updatedEmployee})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the employee was updated successfully
	if result.ModifiedCount == 0 {
		http.Error(w, "Employee not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// DeleteEmployee deletes an employee from the HR system
func (h *EmployeeHandler) DeleteEmployee(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	employeeID := params["id"]

	collection := h.client.Database("hr").Collection("employees")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Delete the employee by ID
	result, err := collection.DeleteOne(ctx, bson.M{"id": employeeID})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Check if the employee was deleted successfully
	if result.DeletedCount == 0 {
		http.Error(w, "Employee not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func concatenateArrays(array1 []string, array2 []string) ([]string, []string) {
	set := make(map[string]bool)
	concatenated := make([]string, 0)
	received := make([]string, 0)

	for _, value := range array1 {
		set[value] = true
		concatenated = append(concatenated, value)
	}

	for _, value := range array2 {
		if !set[value] {
			set[value] = true
			concatenated = append(concatenated, value)
		}
		received = append(received, value)
	}

	return concatenated, received
}
