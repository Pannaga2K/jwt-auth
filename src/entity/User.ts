import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from "typeorm"
import { RefreshToken } from "./RefreshToken";

// REPRESENTS A TABLE IN DB
@Entity()
export class User {

    @PrimaryGeneratedColumn()
    id: number

    @Column()
    username: String;

    @Column()
    email: String;

    @Column()
    password: String;
    
    @OneToMany(type => RefreshToken, refreshToken => refreshToken.user)
    refreshTokens: RefreshToken;
}
