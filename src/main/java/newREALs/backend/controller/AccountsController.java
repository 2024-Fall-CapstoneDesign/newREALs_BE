package newREALs.backend.controller;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import newREALs.backend.domain.Accounts;
import newREALs.backend.dto.*;
import newREALs.backend.repository.UserKeywordRepository;
import newREALs.backend.repository.UserRepository;
import newREALs.backend.service.AttendanceService;
import newREALs.backend.service.KakaoService;
import newREALs.backend.service.ProfileService;
import newREALs.backend.service.TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/accounts")
@RequiredArgsConstructor
public class AccountsController {
    private final KakaoService kakaoService;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final ProfileService profileService;
    private final AttendanceService attendanceService;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create(); // 이렇게 해야 줄바꿈됨
    private final UserKeywordRepository userKeywordRepository;

    //[patch] 출석 체크 버튼 누르기
    @PatchMapping("/attendance/mark")
    public ResponseEntity<?> Checkattendance(HttpServletRequest userInfo){
        try {
            Long userid = tokenService.getUserId(userInfo);
            Map<String, Object> responseBody = new HashMap<>();

            if(attendanceService.UpdateAttendance(userid)){
                responseBody.put("status", "success");
            }else {
                responseBody.put("status", "fail : already checked");
            }

            return ResponseEntity.ok().body(responseBody);

        }catch (Exception e){
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "fail");
            errorResponse.put("error", e.getMessage());

            String errorJsonResponse = gson.toJson(errorResponse);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        }
    }
    //[post] 유저 로그인
    @PostMapping("/login")
    public ResponseEntity<ApiResponseDTO<?>> kakaoLogin(@RequestParam Map<String, String> request) {
        String authorizationCode = request.get("code");
        if (authorizationCode == null || authorizationCode.isBlank()) {
            throw new IllegalArgumentException("인가코드가 비어있습니다.");
        }

        Map<String, Object> kakaoResponse = kakaoService.processKakaoLogin(authorizationCode);
//        Long userId = (Long) kakaoResponse.get("userId");
        String providerId = (String) kakaoResponse.get("providerId");

        // 디비에 유저 있는지 확인
        Optional<Accounts> optionalAccount = userRepository.findByProviderId(providerId);
        Map<String, Object> responseBody = new HashMap<>();

        String redirectUrl;
        if(optionalAccount.isEmpty()) {
            String temporaryToken = tokenService.generateTemporaryToken(providerId);
            responseBody.put("temporary_token", temporaryToken);
            redirectUrl = "/register";
        } else {
            Accounts account = optionalAccount.get();
            boolean hasKeywords = userKeywordRepository.existsByUserId(account.getId());
            if(!hasKeywords) {
                String temporaryToken = tokenService.generateTemporaryToken(providerId);
                responseBody.put("temporary_token", temporaryToken);
                redirectUrl = "/register";
            } else {
                String accessToken = tokenService.generateAccessToken(account);
                String refreshToken = tokenService.generateRefreshToken(account);
                responseBody.put("access_token", accessToken);
                responseBody.put("refresh_token", refreshToken);
                redirectUrl = "/home";
            }
        }

        responseBody.put("redirect_url", redirectUrl);
        responseBody.put("name", kakaoResponse.get("name"));
        responseBody.put("email", kakaoResponse.get("email"));
        responseBody.put("user_id", kakaoResponse.get("userId"));

        return ResponseEntity.ok(ApiResponseDTO.success("로그인 성공", responseBody));

    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request) {

        String refreshToken = tokenService.extractTokenFromHeader(request);

        if (!tokenService.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token입니다.");
        }

        Long userId = tokenService.extractUserIdFromToken(refreshToken);
        Accounts user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("해당 유저를 찾을 수 없습니다."));


        // access token 다시 생성
        String newAccessToken = tokenService.generateAccessToken(user);
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("access_token", newAccessToken);
        return ResponseEntity.ok(ApiResponseDTO.success("Access Token 재발급 성공", responseBody));
    }

}