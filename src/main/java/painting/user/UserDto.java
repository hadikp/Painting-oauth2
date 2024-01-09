package painting.user;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserDto {

    private String userName;
    private String email;
    private Role role;
    private Boolean permit;
    private LocalDate registrationDate;
}
