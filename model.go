package main

// VC 可验证凭证VC
type VC struct {
	BasicVC
	Proof VcProof `json:"proof"` // VC颁发证明，包含颁发放对VC其他所有字段内容的签名
}

// BasicVC 未签名的VC
type BasicVC struct {
	Context           []string `json:"context"`           // VC遵循的规则
	ID                string   `json:"id"`                // 凭证ID [255]
	Types             []string `json:"types"`             // 凭证类型
	CredentialSubject any      `json:"credentialSubject"` // 凭证内容
	Issuer            string   `json:"issuer"`            // 颁发者 [255]
	IssuanceDate      string   `json:"issuanceDate"`      // 颁发时间 [格式：2006-01-02T15:04:05Z]
	ExpirationDate    string   `json:"expirationDate" `   // 失效时间 [格式：2006-01-02T15:04:05Z]
	VCTmplID          string   `json:"vcTmplID"`          // VC模板ID
}

// VcProof VC颁发者证明
type VcProof struct {
	Type               string `json:"type"`               // 签名类型 [255]
	Created            string `json:"created"`            // 证明时间 [格式：2006-01-02T15:04:05Z]
	VerificationMethod string `json:"verificationMethod"` // 该证明的验证方法 [255]
	ProofPurpose       string `json:"proofPurpose"`       // 证明创建原因 (通常为assertionMethod) [255]
	ProofValue         string `json:"proofValue"`         // Base58编码的签名值 [255]
}

// VP 可验证凭证VP
type VP struct {
	BasicVP
	Proof VpProof `json:"proof" binding:"required"` // VC颁发证明，包含颁发放对VC其他所有字段内容的签名
}

// BasicVP 未签名的VP
type BasicVP struct {
	Context              []string  `json:"context" binding:"required,max=8,unique,dive,max=512"` // [必填] VC遵循的规则: 最多8项,每项长度不超过512,每项值唯一
	ID                   string    `json:"id" binding:"required,max=255"`                        // [必填] 凭证ID: 长度不超过255
	Type                 []string  `json:"type" binding:"required,max=10,unique,dive,max=32"`    // [必填] 凭证类型: 最多10项,每项长度不超过32,每项值唯一
	Holder               string    `json:"holder" binding:"required,max=255"`                    // [必填] 持有人账户ID: 长度不超过255
	VerifiableCredential []BasicVC `json:"verifiableCredential" binding:"required"`              // [必填] VC凭证内容
}

// VpProof VC颁发者证明
type VpProof struct {
	Type               string `json:"type" binding:"required,max=255"`                          // [必填] 签名类型: 长度不超过255
	Created            string `json:"created" binding:"required,datetime=2006-01-02T15:04:05Z"` // [必填] 证明时间: [格式：2006-01-02T15:04:05Z]
	VerificationMethod string `json:"verificationMethod" binding:"required,max=255"`            // [必填] 该证明的验证方法: 长度不超过255
	ProofPurpose       string `json:"proofPurpose" binding:"required,max=255"`                  // [必填] 证明创建原因: 通常为assertionMethod,长度不超过255
	ProofValue         string `json:"proofValue" binding:"required,max=512"`                    // [必填] Base58编码的签名值: 长度不超过512
}
