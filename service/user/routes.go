package user

type Handler struct {
}

func NewHandler() *Handler {
	return &Handler{}
}
func (h *Handler) RegisterRoute(router *mux.Router) {
	router.HandleFunc("/login")
}
func (h *Handler) handLogin() {

}
