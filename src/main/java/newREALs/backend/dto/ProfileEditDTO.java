package newREALs.backend.dto;

import lombok.AllArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

@AllArgsConstructor
public class ProfileEditDTO {
    private String newName;
    private MultipartFile file;
}
