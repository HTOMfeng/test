package com.unicomSmartCity.auth.controller;

import com.unicomSmartCity.auth.form.LoginBody;
import com.unicomSmartCity.auth.service.SysLoginService;
import com.unicomSmartCity.common.core.domain.R;
import com.unicomSmartCity.common.core.utils.StringUtils;
import com.unicomSmartCity.common.security.service.TokenService;
import com.unicomSmartCity.system.api.domain.AppUser;
import com.unicomSmartCity.system.api.domain.SysUser;
import com.unicomSmartCity.system.api.model.LoginUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * token 控制
 * 
 * @author unicomSmartCity
 */
@RestController
public class TokenController
{
    @Autowired
    private TokenService tokenService;

    @Autowired
    private SysLoginService sysLoginService;

    @PostMapping("login")
    public R<?> login(@RequestBody LoginBody form)
    {
        // 用户登录
        LoginUser userInfo = sysLoginService.login(form.getUsername(), form.getPassword());
        // 获取登录token
        return R.ok(tokenService.createToken(userInfo));
    }

    @DeleteMapping("logout")
    public R<?> logout(HttpServletRequest request)
    {
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (StringUtils.isNotNull(loginUser))
        {
            String username = loginUser.getUsername();
            // 删除用户缓存记录
            tokenService.delLoginUser(loginUser.getToken());
            // 记录用户退出日志
            sysLoginService.logout(username);
        }
        return R.ok();
    }

    @PostMapping("refresh")
    public R<?> refresh(HttpServletRequest request)
    {
        LoginUser loginUser = tokenService.getLoginUser(request);
        if (StringUtils.isNotNull(loginUser))
        {
            // 刷新令牌有效期
            tokenService.refreshToken(loginUser);
            return R.ok();
        }
        return R.ok();
    }
    /**
     * 忘记密码
     * @param sysUser
     * @return
     */
    @PutMapping("webForgetPassword")
    public R<String> webForgetPassword(@RequestBody SysUser sysUser){
        return sysLoginService.webForgetPassword(sysUser);
    }
}
