package painting.user;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@NoArgsConstructor
@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_name")
    private String userName;

    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    private Boolean permit;

    @Column(name = "registration_date")
    private LocalDate registrationDate;
}
