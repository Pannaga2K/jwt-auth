import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from "typeorm"
import { RefreshToken } from "./RefreshToken";

// REPRESENTS A TABLE IN DB
@Entity()
export class User {

    @PrimaryGeneratedColumn()
    id: number

    @Column()
    username: string

    @Column()
    email: string;

    @Column()
    password: string;
    
    @OneToMany(type => RefreshToken, refreshToken => refreshToken.user)
    refreshTokens: RefreshToken;
}
