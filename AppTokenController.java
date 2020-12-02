package com.unicomSmartCity.auth.controller;

import com.unicomSmartCity.auth.form.AppLoginBody;
import com.unicomSmartCity.auth.service.AppLoginService;
import com.unicomSmartCity.common.core.domain.R;
import com.unicomSmartCity.common.core.utils.StringUtils;
import com.unicomSmartCity.common.security.service.TokenService;
import com.unicomSmartCity.system.api.domain.AppUser;
import com.unicomSmartCity.system.api.model.AppLoginUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * token 控制
 *
 * @author liqi
 */
@RestController
public class AppTokenController
{
    @Autowired
    private TokenService tokenService;

    @Autowired
    private AppLoginService appLoginService;

    /**
     * 登录
     * @param form
     * @return
     */
    @PostMapping("/appLogin")
    public R<?> login(@RequestBody AppLoginBody form)
    {
        // 用户登录
        AppLoginUser userInfo = appLoginService.login(form.getPhone(), form.getPassword());
        // 获取登录token
        return R.ok(tokenService.createAppToken(userInfo));
    }

    /**
     * 退出登录
     * @param request
     * @return
     */
    @PostMapping("appLogout")
    public R<?> logout(HttpServletRequest request)
    {
        AppLoginUser appLoginUser = tokenService.getAppLoginUser(request);
        if (StringUtils.isNotNull(appLoginUser))
        {
            String phone = appLoginUser.getPhone();
            // 删除用户缓存记录
            tokenService.delAppLoginUser(appLoginUser.getToken());
            // 记录用户退出日志
            appLoginService.logout(phone);
        }
        return R.ok(null,"退出登录");
    }

    /**
     * 刷新
     * @param request
     * @return
     */
    @PostMapping("appRefresh")
    public R<?> refresh(HttpServletRequest request)
    {
        AppLoginUser appLoginUser = tokenService.getAppLoginUser(request);
        if (StringUtils.isNotNull(appLoginUser))
        {
            // 刷新令牌有效期
            tokenService.refreshAppToken(appLoginUser);
            return R.ok();
        }
        return R.ok();
    }

    /**
     * 注册
     * @param appUser
     * @return
     */
    @PostMapping("appRegister")
    public R<?> appRegister(@RequestBody AppUser appUser){
        return appLoginService.appRegister(appUser);
    }

    /**
     * 忘记密码
     * @param appUser
     * @return
     */
    @PostMapping("appForgetPassword")
    public R<String> appForgetPassword(@RequestBody AppUser appUser){
        return appLoginService.appForgetPassword(appUser);
    }
}
