package swagger

type AccessTokenSuccess struct {
	AccessToken string `json:"access_token" example:"{access_token}"`
}

type AccessTokenFailure struct {
	Error string `json:"error" example:"invalid access_token"`
}

type GetTokensFailure400 struct {
	Error string `json:"error" example:"invalid user_uuid"`
}

type GetTokensFailure401 struct {
	Error string `json:"error" example:"failed to generate/save tokens"`
}

type GetUUIDSuccess struct {
	UserUUID string `json:"user_uuid" example:"{user_uuid}"`
}

type TokenDataFailure struct {
	Error string `json:"error" example:"missing token data"`
}

type DeauthorizeSuccess struct {
	Message string `json:"message" example:"deauthorized"`
}

type WebhookSuccess struct {
	Message string `json:"message" example:"received"`
}

type WebhookFailure struct {
	Error string `json:"error" example:"JSON binding error"`
}

type WebhookPayload struct {
	UserUUID string `json:"user_uuid" example:"550e8400-e29b-41d4-a716-446655440000"`
	OldIP    string `json:"old_ip"    example:"192.168.1.1"`
	NewIP    string `json:"new_ip"    example:"192.168.1.2"`
	Message  string `json:"message"   example:"ip changed"`
}
