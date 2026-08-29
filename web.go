package main

import (
	"embed"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
)

//go:embed static
var staticFiles embed.FS

// webServer exposes the record table and its add/delete API.
type webServer struct {
	store *store
}

func (w *webServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(staticFiles))
	mux.HandleFunc("GET /{$}", func(rw http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(rw, r, staticFiles, "static/index.html")
	})
	mux.HandleFunc("GET /api/records", w.listRecords)
	mux.HandleFunc("POST /api/records", w.addRecord)
	mux.HandleFunc("DELETE /api/records/{domain}", w.deleteRecord)
	return mux
}

func writeJSON(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	if err := json.NewEncoder(rw).Encode(body); err != nil {
		log.Printf("web: writing response: %v", err)
	}
}

func writeError(rw http.ResponseWriter, status int, message string) {
	writeJSON(rw, status, map[string]string{"error": message})
}

// writeStoreError separates a caller's mistake from ours: bad input is a 400
// with the reason, a failed write is a 500 that only says so in the log.
func writeStoreError(rw http.ResponseWriter, err error) {
	var bad invalidError
	if errors.As(err, &bad) {
		writeError(rw, http.StatusBadRequest, bad.Error())
		return
	}
	log.Printf("web: saving records: %v", err)
	writeError(rw, http.StatusInternalServerError, "could not save records")
}

func (w *webServer) listRecords(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, http.StatusOK, w.store.list())
}

func (w *webServer) addRecord(rw http.ResponseWriter, r *http.Request) {
	var in record
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4096)).Decode(&in); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := w.store.set(in.Domain, in.IP); err != nil {
		writeStoreError(rw, err)
		return
	}
	log.Printf("web: set %s -> %s", normalize(in.Domain), strings.TrimSpace(in.IP))
	writeJSON(rw, http.StatusOK, w.store.list())
}

func (w *webServer) deleteRecord(rw http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	deleted, err := w.store.delete(domain)
	if err != nil {
		writeStoreError(rw, err)
		return
	}
	if !deleted {
		writeError(rw, http.StatusNotFound, "no such record")
		return
	}
	log.Printf("web: deleted %s", normalize(domain))
	writeJSON(rw, http.StatusOK, w.store.list())
}
