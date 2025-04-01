import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from "typeorm";

@Entity()
export class User {
    @PrimaryGeneratedColumn("uuid")
    id!: string;

    @Column({ type: "varchar", unique: true })
    email!: string;

    @Column({ type: "varchar" })
    password!: string;

    @Column({ type: "varchar", nullable: true })
    name!: string;

    @Column({ type: "varchar", nullable: true })
    phone!: string;

    @Column({ type: "varchar", nullable: true })
    profileImage!: string;

    @CreateDateColumn({ type: "timestamp" })
    createdAt!: Date;

    @UpdateDateColumn({ type: "timestamp" })
    updatedAt!: Date;
} 