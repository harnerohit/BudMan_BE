package in.sct.moneymanager.service;

import in.sct.moneymanager.util.JwtUtil;
import in.sct.moneymanager.dto.AuthDTO;
import in.sct.moneymanager.dto.ProfileDTO;
import in.sct.moneymanager.entity.ProfileEntity;
import in.sct.moneymanager.repository.ProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final ProfileRepository profileRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    // ✅ REGISTER (AUTO-ACTIVATED)
    public ProfileDTO registerProfile(ProfileDTO profileDTO) {

        ProfileEntity newProfile = ProfileEntity.builder()
                .fullName(profileDTO.getFullName())
                .email(profileDTO.getEmail())
                .password(passwordEncoder.encode(profileDTO.getPassword()))
                .profileImageUrl(profileDTO.getProfileImageUrl())
                .isActive(true)          // ✅ IMPORTANT FIX
                .activationToken(null)   // ✅ NO EMAIL ACTIVATION
                .build();

        ProfileEntity savedProfile = profileRepository.save(newProfile);
        return toDTO(savedProfile);
    }

    // DTO → Entity helpers
    public ProfileDTO toDTO(ProfileEntity profileEntity) {
        return ProfileDTO.builder()
                .id(profileEntity.getId())
                .fullName(profileEntity.getFullName())
                .email(profileEntity.getEmail())
                .profileImageUrl(profileEntity.getProfileImageUrl())
                .createdAt(profileEntity.getCreatedAt())
                .updatedAt(profileEntity.getUpdatedAt())
                .build();
    }

    // ❌ NOT USED IN OPTION 1 (KEPT FOR FUTURE)
    public boolean activateProfile(String activationToken) {
        return false;
    }

    // ✅ LOGIN ACTIVE CHECK (NO CHANGE)
    public boolean isAccountActive(String email) {
        return profileRepository.findByEmail(email)
                .map(ProfileEntity::getIsActive)
                .orElse(false);
    }

    // ✅ CURRENT USER
    public ProfileEntity getCurrentProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return profileRepository.findByEmail(authentication.getName())
                .orElseThrow(() ->
                        new UsernameNotFoundException("Profile not found with email: " + authentication.getName()));
    }

    // ✅ PUBLIC PROFILE
    public ProfileDTO getPublicProfile(String email) {
        ProfileEntity user;

        if (email == null) {
            user = getCurrentProfile();
        } else {
            user = profileRepository.findByEmail(email)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("Profile not found with email: " + email));
        }

        return toDTO(user);
    }

    // ✅ LOGIN + JWT (UNCHANGED)
    public Map<String, Object> authenticateAndGenerateToken(AuthDTO authDTO) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authDTO.getEmail(),
                            authDTO.getPassword()
                    )
            );

            String token = jwtUtil.generateToken(authDTO.getEmail());

            return Map.of(
                    "token", token,
                    "user", getPublicProfile(authDTO.getEmail())
            );
        } catch (Exception e) {
            throw new RuntimeException("Invalid email or password");
        }
    }
}
