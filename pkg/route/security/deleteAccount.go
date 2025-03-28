package security

import (
	"github.com/emersion/go-msgauth/dkim"
	"regexp"
	stdmail "net/mail" // 使用标准库 net/mail，别名 stdmail
	"fmt"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"gorm.io/gorm"
	"net/http"
	"strconv"
	"strings"
	"treehollow-v3-backend/pkg/base"
	"treehollow-v3-backend/pkg/consts"
	"treehollow-v3-backend/pkg/logger"
	"treehollow-v3-backend/pkg/utils"
)

func deleteAccount(c *gin.Context) {
	email := strings.ToLower(c.PostForm("email"))
	emailHash := utils.HashEmail(email)
	nonce := c.PostForm("nonce")
	code := c.PostForm("valid_code")
	//now := utils.GetTimeStamp()
	if len(nonce) < 10 {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("NonceNotEnoughLong", "Nonce错误", logger.INFO))
		return
	}

	emailHeader := code
	if emailHeader == "" {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("MissingEmailHeader", "请提供邮件内容", logger.INFO))
		return
	}
	emailWhitelist := viper.GetStringSlice("email_whitelist")
	if _, ok := utils.ContainsString(emailWhitelist, email); ok {
		if emailHeader != viper.GetString("whitelist_user_create_account_passcode") {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("InvalidWhitelistUserCreateAccountCode", "请输入正确的白名单用户通行口令", logger.ERROR))
		return
		}
	}else{
		emailRegexStr := viper.GetString("email_header_regex")
		if emailRegexStr == "" {
			emailRegexStr = `^(?i:.*dkim-signature:)(?i:.*from:)(?i:.*to:).+`
		}
		emailRegex, err := regexp.Compile(emailRegexStr)
		if err != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("RegexCompileError", "服务器配置错误，请联系管理员", logger.ERROR))
			return
		}
		if !emailRegex.MatchString(emailHeader) {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("InvalidEmailHeader", "邮件格式不正确或缺少DKIM签名", logger.INFO))
			return
		}
		emailReader := strings.NewReader(emailHeader)
		emailMsg, err := stdmail.ReadMessage(emailReader)
		if err != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("ParseEmailHeaderError", "无法解析邮件", logger.INFO))
			return
		}
		emailRealHeader := emailMsg.Header
		//必须说明，这里的emailRealHeader才是"net/mail"中真正定义的Header，用户界面上显示的"信头"以及前端来的"email_header"等都是为了理解上的方便，其实应该叫"email_content"
		if err != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("GetEmailRealHeaderError", "无法从邮件内容解析邮件信头", logger.INFO))
			return
		}
		toAddressList, err := emailRealHeader.AddressList("To")
		if err != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("InvalidEmailHeader", "邮件格式不正确，或许删除头尾多余的换行？", logger.INFO))
			return
		}
		if len(toAddressList) == 0 {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("InvalidToField", "收件人缺失或异常", logger.INFO))
			return
		}
		matched := false
		for _, addr := range toAddressList {
			if strings.EqualFold(addr.Address, email) {
				matched = true
				break
			}
		}
		if !matched {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("ToMismatch", "邮件收件人不匹配注册邮箱", logger.INFO))
			return
		}

		fromAddress, err := stdmail.ParseAddress(emailRealHeader.Get("From"))
		if err != nil || len(fromAddress.Address) == 0 {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("InvalidFromField", "发件人缺失或异常", logger.INFO))
			return
		}
		trustedDomains := viper.GetStringSlice("trusted_from_domains")
		validDomain := false
		for _, domain := range trustedDomains {
			if strings.HasSuffix(strings.ToLower(fromAddress.Address), strings.ToLower(domain)) {
				validDomain = true
				break
			}
		}
		if !validDomain {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("UntrustedFromDomain", "发件人邮箱不在受信任域名列表中。", logger.INFO))
			return
		}
		
		normalizedEmailHeader := strings.ReplaceAll(emailHeader, "\n", "\r\n")
		normalizedEmailReader := strings.NewReader(normalizedEmailHeader)
		verifications, err := dkim.Verify(normalizedEmailReader)
		if err != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(err, "DKIMVerifyError", "DKIM签名验证错误，请联系管理员。"))
			return
		}
		dkimPass := false
		dkimAllPass := true
		for count, v := range verifications {
			if v.Err == nil {
				dkimPass = true
			}else{
				dkimAllPass = false
			}
			fmt.Println(count)
			fmt.Println(v.Domain, v.Err)
			if count >= 64 {
				dkimAllPass = false
				break
			}
		}
		if !(dkimPass == true && dkimAllPass == true) {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("DKIMSignatureInvalid", "DKIM签名验证不通过", logger.INFO))
			return
		}
	}
	/*correctCode, timeStamp, failedTimes, err2 := base.GetVerificationCode(emailHash)
	if err2 != nil && !errors.Is(err2, gorm.ErrRecordNotFound) {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(err2, "QueryValidCodeFailed", consts.DatabaseReadFailedString))
		return
	}
	if failedTimes >= 10 && now-timeStamp <= 43200 {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("ValidCodeTooMuchFailed", "验证码错误尝试次数过多，请重新发送验证码", logger.INFO))
		return
	}
	if correctCode != code || now-timeStamp > 43200 {
		base.HttpReturnWithErrAndAbort(c, -10, logger.NewSimpleError("ValidCodeInvalid", "验证码无效或过期", logger.WARN))
		_ = base.GetDb(false).Model(&base.VerificationCode{}).Where("email_hash = ?", emailHash).
			Update("failed_times", gorm.Expr("failed_times + 1")).Error
		return
	}*/

	_ = base.GetDb(false).Transaction(func(tx *gorm.DB) error {
		var user base.User
		err := tx.Model(&base.User{}).Where("forget_pw_nonce = ?", nonce).First(&user).Error

		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				base.HttpReturnWithCodeMinusOne(c, logger.NewSimpleError("NonceNotFound",
					"没有找到nonce对应的账户。请你重新查看刚刚注册树洞后收到的欢迎邮件中的“找回密码口令”(nonce)。"+
						"如果仍然无法解决问题，请联系"+viper.GetString("contact_email")+"。", logger.WARN))
				return errors.New("NonceNotFound")
			}
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(err, "DeleteNonceFailed", consts.DatabaseReadFailedString))
			return err
		}

		if user.Role == base.BannedUserRole {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("DeleteAccountFrozen",
				"您的账户已被冻结，无法注销。如果需要解冻，请联系"+
					viper.GetString("contact_email")+"。", logger.ERROR))

			return errors.New("DeleteBannedAccount")
		}

		if user.CreatedAt.After(utils.GetEarliestAuthenticationTime()) {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("DeleteJustRegisteredAccount",
				"注销失败，账户需要注册"+strconv.Itoa(consts.TokenExpireDays)+"天以上才可以注销。", logger.ERROR))

			return errors.New("DeleteJustRegisteredAccount")
		}

		timestamp := utils.GetTimeStamp()
		var count int64
		err3 := tx.Model(&base.Ban{}).Where("user_id = ? and expire_at > ?", user.ID, timestamp).Count(&count).Error
		if err3 != nil {
			base.HttpReturnWithCodeMinusOne(c, logger.NewError(err3, "GetBanFailed", consts.DatabaseReadFailedString))
			return err3
		}

		if count > 0 {
			base.HttpReturnWithCodeMinusOneAndAbort(c,
				logger.NewSimpleError("DisallowDeleteWhileBan", "很抱歉，您当前处于禁言状态，无法注销。", logger.ERROR))
			return errors.New("DisallowDeleteWhileBan")
		}

		result := tx.Where("forget_pw_nonce = ?", nonce).
			Delete(&base.User{})

		if result.Error != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(result.Error, "DeleteNonceFailed", consts.DatabaseWriteFailedString))
			return result.Error
		}

		result = tx.Where("email_hash = ?", emailHash).
			Delete(&base.Email{})

		if result.Error != nil {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(result.Error, "DeleteEmailHashFailed", consts.DatabaseWriteFailedString))
			return result.Error
		}

		if result.RowsAffected == 0 {
			base.HttpReturnWithCodeMinusOne(c, logger.NewSimpleError("EmailNotFound",
				"没有找到此邮箱对应的账户", logger.WARN))
			return errors.New("EmailNotFound")
		}

		c.JSON(http.StatusOK, gin.H{
			"code": 0,
		})
		return nil
	})
}
