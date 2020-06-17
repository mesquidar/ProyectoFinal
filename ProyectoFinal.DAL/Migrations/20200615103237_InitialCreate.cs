using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace ProyectoFinal.DAL.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AspNetRoles",
                columns: table => new
                {
                    Id = table.Column<string>(nullable: false),
                    Name = table.Column<string>(maxLength: 256, nullable: true),
                    NormalizedName = table.Column<string>(maxLength: 256, nullable: true),
                    ConcurrencyStamp = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUsers",
                columns: table => new
                {
                    Id = table.Column<string>(nullable: false),
                    UserName = table.Column<string>(maxLength: 256, nullable: true),
                    NormalizedUserName = table.Column<string>(maxLength: 256, nullable: true),
                    Email = table.Column<string>(maxLength: 256, nullable: true),
                    NormalizedEmail = table.Column<string>(maxLength: 256, nullable: true),
                    EmailConfirmed = table.Column<bool>(nullable: false),
                    PasswordHash = table.Column<string>(nullable: true),
                    SecurityStamp = table.Column<string>(nullable: true),
                    ConcurrencyStamp = table.Column<string>(nullable: true),
                    PhoneNumber = table.Column<string>(nullable: true),
                    PhoneNumberConfirmed = table.Column<bool>(nullable: false),
                    TwoFactorEnabled = table.Column<bool>(nullable: false),
                    LockoutEnd = table.Column<DateTimeOffset>(nullable: true),
                    LockoutEnabled = table.Column<bool>(nullable: false),
                    AccessFailedCount = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUsers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AspNetRoleClaims",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    RoleId = table.Column<string>(nullable: false),
                    ClaimType = table.Column<string>(nullable: true),
                    ClaimValue = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetRoleClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetRoleClaims_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserClaims",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<string>(nullable: false),
                    ClaimType = table.Column<string>(nullable: true),
                    ClaimValue = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserClaims", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AspNetUserClaims_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserLogins",
                columns: table => new
                {
                    LoginProvider = table.Column<string>(maxLength: 128, nullable: false),
                    ProviderKey = table.Column<string>(maxLength: 128, nullable: false),
                    ProviderDisplayName = table.Column<string>(nullable: true),
                    UserId = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserLogins", x => new { x.LoginProvider, x.ProviderKey });
                    table.ForeignKey(
                        name: "FK_AspNetUserLogins_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserRoles",
                columns: table => new
                {
                    UserId = table.Column<string>(nullable: false),
                    RoleId = table.Column<string>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetRoles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "AspNetRoles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AspNetUserRoles_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AspNetUserTokens",
                columns: table => new
                {
                    UserId = table.Column<string>(nullable: false),
                    LoginProvider = table.Column<string>(maxLength: 128, nullable: false),
                    Name = table.Column<string>(maxLength: 128, nullable: false),
                    Value = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AspNetUserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                    table.ForeignKey(
                        name: "FK_AspNetUserTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Malwares",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    User_Id = table.Column<string>(nullable: true),
                    Date = table.Column<DateTime>(nullable: false),
                    MD5 = table.Column<string>(nullable: true),
                    SHA256 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    FileName = table.Column<string>(nullable: true),
                    FilePath = table.Column<string>(nullable: true),
                    Url = table.Column<string>(nullable: true),
                    MalwareStatus = table.Column<int>(nullable: false),
                    MalwareLevel = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Malwares", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Malwares_AspNetUsers_User_Id",
                        column: x => x.User_Id,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Comments",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    User_Id = table.Column<string>(nullable: true),
                    Malware_Id = table.Column<int>(nullable: false),
                    TextComment = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Comments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Comments_Malwares_Malware_Id",
                        column: x => x.Malware_Id,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Comments_AspNetUsers_User_Id",
                        column: x => x.User_Id,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooInfos",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooScanId = table.Column<int>(nullable: false),
                    MD5 = table.Column<string>(nullable: true),
                    MalwareId = table.Column<int>(nullable: true),
                    Malware_Id = table.Column<int>(nullable: false),
                    Category = table.Column<string>(nullable: true),
                    Package = table.Column<string>(nullable: true),
                    Score = table.Column<float>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooInfos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooInfos_Malwares_MalwareId",
                        column: x => x.MalwareId,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ScreenShots",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    PathFile = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScreenShots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScreenShots_Malwares_Malware_Id",
                        column: x => x.Malware_Id,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ThreatCrowdInfo",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Malware_Id = table.Column<int>(nullable: false),
                    Type = table.Column<string>(nullable: true),
                    Votes = table.Column<int>(nullable: false),
                    Permalink = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatCrowdInfo", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ThreatCrowdInfo_Malwares_Malware_Id",
                        column: x => x.Malware_Id,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalInfos",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MD5 = table.Column<string>(nullable: true),
                    Malware_Id = table.Column<int>(nullable: false),
                    Total = table.Column<int>(nullable: false),
                    Positives = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalInfos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalInfos_Malwares_Malware_Id",
                        column: x => x.Malware_Id,
                        principalTable: "Malwares",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CuckooBehaviors",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooInfoId = table.Column<int>(nullable: true),
                    CuckooScan_Id = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooBehaviors", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooBehaviors_CuckooInfos_CuckooInfoId",
                        column: x => x.CuckooInfoId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooDroppeds",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooScanId = table.Column<int>(nullable: true),
                    CuckooScan_Id = table.Column<int>(nullable: false),
                    crc32 = table.Column<string>(nullable: true),
                    FilePath = table.Column<string>(nullable: true),
                    md5 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Path = table.Column<string>(nullable: true),
                    Size = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooDroppeds", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooDroppeds_CuckooInfos_CuckooScanId",
                        column: x => x.CuckooScanId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooSignatures",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooScanId = table.Column<int>(nullable: true),
                    CuckooScan_Id = table.Column<int>(nullable: false),
                    Description = table.Column<string>(nullable: true),
                    Markcount = table.Column<int>(nullable: false),
                    Severity = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooSignatures", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooSignatures_CuckooInfos_CuckooScanId",
                        column: x => x.CuckooScanId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooStatics",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooScanId = table.Column<int>(nullable: true),
                    CuckooScan_Id = table.Column<int>(nullable: false),
                    ImportedDllCount = table.Column<int>(nullable: false),
                    PeImphash = table.Column<string>(nullable: true),
                    PeTimestamp = table.Column<DateTime>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooStatics", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooStatics_CuckooInfos_CuckooScanId",
                        column: x => x.CuckooScanId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooStrings",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckoScanId = table.Column<int>(nullable: true),
                    CuckooScan_Id = table.Column<int>(nullable: false),
                    Strings = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooStrings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooStrings_CuckooInfos_CuckoScanId",
                        column: x => x.CuckoScanId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "CuckooTargets",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckoScanId = table.Column<int>(nullable: true),
                    CuckooScan_Id = table.Column<int>(nullable: false),
                    crc32 = table.Column<string>(nullable: true),
                    FilePath = table.Column<string>(nullable: true),
                    md5 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Path = table.Column<string>(nullable: true),
                    Size = table.Column<int>(nullable: false),
                    Ssdeep = table.Column<string>(nullable: true),
                    Type = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CuckooTargets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CuckooTargets_CuckooInfos_CuckoScanId",
                        column: x => x.CuckoScanId,
                        principalTable: "CuckooInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCDomains",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    Domain = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCDomains", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCDomains_ThreatCrowdInfo_ThreatCrowd_Id",
                        column: x => x.ThreatCrowd_Id,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TCEmails",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    Email = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCEmails", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCEmails_ThreatCrowdInfo_ThreatCrowd_Id",
                        column: x => x.ThreatCrowd_Id,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TCHashes",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Hash = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCHashes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCHashes_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCIps",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    Ip = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCIps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCIps_ThreatCrowdInfo_ThreatCrowd_Id",
                        column: x => x.ThreatCrowd_Id,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TCReferences",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    Reference = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCReferences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCReferences_ThreatCrowdInfo_ThreatCrowd_Id",
                        column: x => x.ThreatCrowd_Id,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TCResolutions",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    LastResolved = table.Column<string>(nullable: true),
                    Ip = table.Column<string>(nullable: true),
                    Domain = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCResolutions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCResolutions_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TCScans",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    Scan = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCScans", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCScans_ThreatCrowdInfo_ThreatCrowd_Id",
                        column: x => x.ThreatCrowd_Id,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TCSubdomanins",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ThreatCrowd_Id = table.Column<int>(nullable: false),
                    ThreatCrowdInfoId = table.Column<int>(nullable: true),
                    Subdomain = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TCSubdomanins", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TCSubdomanins_ThreatCrowdInfo_ThreatCrowdInfoId",
                        column: x => x.ThreatCrowdInfoId,
                        principalTable: "ThreatCrowdInfo",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalComments",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    VirusTotal_Id = table.Column<int>(nullable: false),
                    VirusTotalId = table.Column<int>(nullable: true),
                    Date = table.Column<DateTime>(nullable: false),
                    Comment = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalComments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalComments_VirusTotalInfos_VirusTotalId",
                        column: x => x.VirusTotalId,
                        principalTable: "VirusTotalInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "VirusTotalScans",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    VirusTotal_Id = table.Column<int>(nullable: false),
                    Name = table.Column<string>(nullable: true),
                    Detected = table.Column<bool>(nullable: false),
                    Result = table.Column<string>(nullable: true),
                    Version = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VirusTotalScans", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VirusTotalScans_VirusTotalInfos_VirusTotal_Id",
                        column: x => x.VirusTotal_Id,
                        principalTable: "VirusTotalInfos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "BehaviorSummaries",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Behavior_Id = table.Column<int>(nullable: false),
                    Name = table.Column<string>(nullable: true),
                    Strings = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BehaviorSummaries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BehaviorSummaries_CuckooBehaviors_Behavior_Id",
                        column: x => x.Behavior_Id,
                        principalTable: "CuckooBehaviors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ProcessTrees",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Behavior_Id = table.Column<int>(nullable: false),
                    CommandLine = table.Column<string>(nullable: true),
                    FirstSeen = table.Column<double>(nullable: false),
                    Pid = table.Column<long>(nullable: false),
                    Ppid = table.Column<long>(nullable: false),
                    ProcessName = table.Column<string>(nullable: true),
                    Track = table.Column<bool>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessTrees", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ProcessTrees_CuckooBehaviors_Behavior_Id",
                        column: x => x.Behavior_Id,
                        principalTable: "CuckooBehaviors",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DroppedPids",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Dropped_Id = table.Column<int>(nullable: false),
                    Pid = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DroppedPids", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DroppedPids_CuckooDroppeds_Dropped_Id",
                        column: x => x.Dropped_Id,
                        principalTable: "CuckooDroppeds",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DroppedUrls",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooDroppedId = table.Column<int>(nullable: true),
                    Dropped_Id = table.Column<int>(nullable: false),
                    Url = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DroppedUrls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DroppedUrls_CuckooDroppeds_CuckooDroppedId",
                        column: x => x.CuckooDroppedId,
                        principalTable: "CuckooDroppeds",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "YaraDroppeds",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Dropped_Id = table.Column<int>(nullable: false),
                    crc32 = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Description = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_YaraDroppeds", x => x.Id);
                    table.ForeignKey(
                        name: "FK_YaraDroppeds_CuckooDroppeds_Dropped_Id",
                        column: x => x.Dropped_Id,
                        principalTable: "CuckooDroppeds",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Marks",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Siganture_Id = table.Column<int>(nullable: false),
                    Cid = table.Column<int>(nullable: true),
                    Pid = table.Column<int>(nullable: true),
                    Type = table.Column<string>(nullable: true),
                    Category = table.Column<string>(nullable: true),
                    Description = table.Column<string>(nullable: true),
                    Ioc = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Marks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Marks_CuckooSignatures_Siganture_Id",
                        column: x => x.Siganture_Id,
                        principalTable: "CuckooSignatures",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SignatureReferences",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooSignature_Id = table.Column<int>(nullable: false),
                    References = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SignatureReferences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SignatureReferences_CuckooSignatures_CuckooSignature_Id",
                        column: x => x.CuckooSignature_Id,
                        principalTable: "CuckooSignatures",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PeExports",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooStatic_Id = table.Column<int>(nullable: false),
                    Dll = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeExports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeExports_CuckooStatics_CuckooStatic_Id",
                        column: x => x.CuckooStatic_Id,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PeImports",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooStatic_Id = table.Column<int>(nullable: false),
                    Dll = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeImports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeImports_CuckooStatics_CuckooStatic_Id",
                        column: x => x.CuckooStatic_Id,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PeResources",
                columns: table => new
                {
                    id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Static_Id = table.Column<int>(nullable: false),
                    Filetype = table.Column<string>(nullable: true),
                    Language = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true),
                    Offset = table.Column<string>(nullable: true),
                    Size = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeResources", x => x.id);
                    table.ForeignKey(
                        name: "FK_PeResources_CuckooStatics_Static_Id",
                        column: x => x.Static_Id,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PeSections",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Static_Id = table.Column<int>(nullable: false),
                    Entropy = table.Column<double>(nullable: false),
                    Name = table.Column<string>(nullable: true),
                    SizeOfData = table.Column<string>(nullable: true),
                    VirtualAddress = table.Column<string>(nullable: true),
                    VirtualSize = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PeSections", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PeSections_CuckooStatics_Static_Id",
                        column: x => x.Static_Id,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StaticKeys",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    CuckooStatic_Id = table.Column<int>(nullable: false),
                    Keys = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StaticKeys", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StaticKeys_CuckooStatics_CuckooStatic_Id",
                        column: x => x.CuckooStatic_Id,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "StaticSignatures",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Static_Id = table.Column<int>(nullable: false),
                    CommonName = table.Column<string>(nullable: true),
                    Country = table.Column<string>(nullable: true),
                    Email = table.Column<string>(nullable: true),
                    Locality = table.Column<string>(nullable: true),
                    Organization = table.Column<string>(nullable: true),
                    SerialNumber = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StaticSignatures", x => x.Id);
                    table.ForeignKey(
                        name: "FK_StaticSignatures_CuckooStatics_Static_Id",
                        column: x => x.Static_Id,
                        principalTable: "CuckooStatics",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TargetPids",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Target_Id = table.Column<int>(nullable: false),
                    Pid = table.Column<int>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TargetPids", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TargetPids_CuckooTargets_Target_Id",
                        column: x => x.Target_Id,
                        principalTable: "CuckooTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TargetUrls",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Target_Id = table.Column<int>(nullable: false),
                    Url = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TargetUrls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TargetUrls_CuckooTargets_Target_Id",
                        column: x => x.Target_Id,
                        principalTable: "CuckooTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MarkCalls",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Mark_Id = table.Column<int>(nullable: false),
                    Api = table.Column<string>(nullable: true),
                    Category = table.Column<string>(nullable: true),
                    Status = table.Column<long>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkCalls", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MarkCalls_Marks_Mark_Id",
                        column: x => x.Mark_Id,
                        principalTable: "Marks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MarkSections",
                columns: table => new
                {
                    id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Mark_Id = table.Column<int>(nullable: false),
                    Entropy = table.Column<long>(nullable: false),
                    Name = table.Column<string>(nullable: true),
                    SizeOfData = table.Column<string>(nullable: true),
                    VirtualAddress = table.Column<string>(nullable: true),
                    VirtualSize = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkSections", x => x.id);
                    table.ForeignKey(
                        name: "FK_MarkSections_Marks_Mark_Id",
                        column: x => x.Mark_Id,
                        principalTable: "Marks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Exports",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PeExport_Id = table.Column<int>(nullable: false),
                    Address = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Exports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Exports_PeExports_PeExport_Id",
                        column: x => x.PeExport_Id,
                        principalTable: "PeExports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Imports",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PeImport_Id = table.Column<int>(nullable: false),
                    Address = table.Column<string>(nullable: true),
                    Name = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Imports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Imports_PeImports_PeImport_Id",
                        column: x => x.PeImport_Id,
                        principalTable: "PeImports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MarkArguments",
                columns: table => new
                {
                    Id = table.Column<int>(nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    MarkCall_Id = table.Column<int>(nullable: false),
                    BaseAddress = table.Column<string>(nullable: true),
                    Length = table.Column<long>(nullable: true),
                    ProcessHandle = table.Column<string>(nullable: true),
                    ProcessIdentifier = table.Column<int>(nullable: true),
                    Protection = table.Column<int>(nullable: true),
                    AllocationType = table.Column<long>(nullable: true),
                    RegionSize = table.Column<long>(nullable: true),
                    FreeBytes = table.Column<long>(nullable: true),
                    RootPath = table.Column<string>(nullable: true),
                    TotalNumberOfBytes = table.Column<double>(nullable: true),
                    TotalNumberOfFreeBytes = table.Column<long>(nullable: true),
                    Access = table.Column<string>(nullable: true),
                    BaseHandle = table.Column<string>(nullable: true),
                    KeyHandle = table.Column<string>(nullable: true),
                    Options = table.Column<long>(nullable: true),
                    Regkey = table.Column<string>(nullable: true),
                    RegkeyR = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MarkArguments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MarkArguments_MarkCalls_MarkCall_Id",
                        column: x => x.MarkCall_Id,
                        principalTable: "MarkCalls",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AspNetRoleClaims_RoleId",
                table: "AspNetRoleClaims",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "RoleNameIndex",
                table: "AspNetRoles",
                column: "NormalizedName",
                unique: true,
                filter: "[NormalizedName] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserClaims_UserId",
                table: "AspNetUserClaims",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserLogins_UserId",
                table: "AspNetUserLogins",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUserRoles_RoleId",
                table: "AspNetUserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "EmailIndex",
                table: "AspNetUsers",
                column: "NormalizedEmail");

            migrationBuilder.CreateIndex(
                name: "UserNameIndex",
                table: "AspNetUsers",
                column: "NormalizedUserName",
                unique: true,
                filter: "[NormalizedUserName] IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_BehaviorSummaries_Behavior_Id",
                table: "BehaviorSummaries",
                column: "Behavior_Id");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_Malware_Id",
                table: "Comments",
                column: "Malware_Id");

            migrationBuilder.CreateIndex(
                name: "IX_Comments_User_Id",
                table: "Comments",
                column: "User_Id");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooBehaviors_CuckooInfoId",
                table: "CuckooBehaviors",
                column: "CuckooInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooDroppeds_CuckooScanId",
                table: "CuckooDroppeds",
                column: "CuckooScanId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooInfos_MalwareId",
                table: "CuckooInfos",
                column: "MalwareId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooSignatures_CuckooScanId",
                table: "CuckooSignatures",
                column: "CuckooScanId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooStatics_CuckooScanId",
                table: "CuckooStatics",
                column: "CuckooScanId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooStrings_CuckoScanId",
                table: "CuckooStrings",
                column: "CuckoScanId");

            migrationBuilder.CreateIndex(
                name: "IX_CuckooTargets_CuckoScanId",
                table: "CuckooTargets",
                column: "CuckoScanId");

            migrationBuilder.CreateIndex(
                name: "IX_DroppedPids_Dropped_Id",
                table: "DroppedPids",
                column: "Dropped_Id");

            migrationBuilder.CreateIndex(
                name: "IX_DroppedUrls_CuckooDroppedId",
                table: "DroppedUrls",
                column: "CuckooDroppedId");

            migrationBuilder.CreateIndex(
                name: "IX_Exports_PeExport_Id",
                table: "Exports",
                column: "PeExport_Id");

            migrationBuilder.CreateIndex(
                name: "IX_Imports_PeImport_Id",
                table: "Imports",
                column: "PeImport_Id");

            migrationBuilder.CreateIndex(
                name: "IX_Malwares_User_Id",
                table: "Malwares",
                column: "User_Id");

            migrationBuilder.CreateIndex(
                name: "IX_MarkArguments_MarkCall_Id",
                table: "MarkArguments",
                column: "MarkCall_Id");

            migrationBuilder.CreateIndex(
                name: "IX_MarkCalls_Mark_Id",
                table: "MarkCalls",
                column: "Mark_Id");

            migrationBuilder.CreateIndex(
                name: "IX_Marks_Siganture_Id",
                table: "Marks",
                column: "Siganture_Id");

            migrationBuilder.CreateIndex(
                name: "IX_MarkSections_Mark_Id",
                table: "MarkSections",
                column: "Mark_Id");

            migrationBuilder.CreateIndex(
                name: "IX_PeExports_CuckooStatic_Id",
                table: "PeExports",
                column: "CuckooStatic_Id");

            migrationBuilder.CreateIndex(
                name: "IX_PeImports_CuckooStatic_Id",
                table: "PeImports",
                column: "CuckooStatic_Id");

            migrationBuilder.CreateIndex(
                name: "IX_PeResources_Static_Id",
                table: "PeResources",
                column: "Static_Id");

            migrationBuilder.CreateIndex(
                name: "IX_PeSections_Static_Id",
                table: "PeSections",
                column: "Static_Id");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessTrees_Behavior_Id",
                table: "ProcessTrees",
                column: "Behavior_Id");

            migrationBuilder.CreateIndex(
                name: "IX_ScreenShots_Malware_Id",
                table: "ScreenShots",
                column: "Malware_Id");

            migrationBuilder.CreateIndex(
                name: "IX_SignatureReferences_CuckooSignature_Id",
                table: "SignatureReferences",
                column: "CuckooSignature_Id");

            migrationBuilder.CreateIndex(
                name: "IX_StaticKeys_CuckooStatic_Id",
                table: "StaticKeys",
                column: "CuckooStatic_Id");

            migrationBuilder.CreateIndex(
                name: "IX_StaticSignatures_Static_Id",
                table: "StaticSignatures",
                column: "Static_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TargetPids_Target_Id",
                table: "TargetPids",
                column: "Target_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TargetUrls_Target_Id",
                table: "TargetUrls",
                column: "Target_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TCDomains_ThreatCrowd_Id",
                table: "TCDomains",
                column: "ThreatCrowd_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TCEmails_ThreatCrowd_Id",
                table: "TCEmails",
                column: "ThreatCrowd_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TCHashes_ThreatCrowdInfoId",
                table: "TCHashes",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCIps_ThreatCrowd_Id",
                table: "TCIps",
                column: "ThreatCrowd_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TCReferences_ThreatCrowd_Id",
                table: "TCReferences",
                column: "ThreatCrowd_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TCResolutions_ThreatCrowdInfoId",
                table: "TCResolutions",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_TCScans_ThreatCrowd_Id",
                table: "TCScans",
                column: "ThreatCrowd_Id");

            migrationBuilder.CreateIndex(
                name: "IX_TCSubdomanins_ThreatCrowdInfoId",
                table: "TCSubdomanins",
                column: "ThreatCrowdInfoId");

            migrationBuilder.CreateIndex(
                name: "IX_ThreatCrowdInfo_Malware_Id",
                table: "ThreatCrowdInfo",
                column: "Malware_Id");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalComments_VirusTotalId",
                table: "VirusTotalComments",
                column: "VirusTotalId");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalInfos_Malware_Id",
                table: "VirusTotalInfos",
                column: "Malware_Id");

            migrationBuilder.CreateIndex(
                name: "IX_VirusTotalScans_VirusTotal_Id",
                table: "VirusTotalScans",
                column: "VirusTotal_Id");

            migrationBuilder.CreateIndex(
                name: "IX_YaraDroppeds_Dropped_Id",
                table: "YaraDroppeds",
                column: "Dropped_Id");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AspNetRoleClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserClaims");

            migrationBuilder.DropTable(
                name: "AspNetUserLogins");

            migrationBuilder.DropTable(
                name: "AspNetUserRoles");

            migrationBuilder.DropTable(
                name: "AspNetUserTokens");

            migrationBuilder.DropTable(
                name: "BehaviorSummaries");

            migrationBuilder.DropTable(
                name: "Comments");

            migrationBuilder.DropTable(
                name: "CuckooStrings");

            migrationBuilder.DropTable(
                name: "DroppedPids");

            migrationBuilder.DropTable(
                name: "DroppedUrls");

            migrationBuilder.DropTable(
                name: "Exports");

            migrationBuilder.DropTable(
                name: "Imports");

            migrationBuilder.DropTable(
                name: "MarkArguments");

            migrationBuilder.DropTable(
                name: "MarkSections");

            migrationBuilder.DropTable(
                name: "PeResources");

            migrationBuilder.DropTable(
                name: "PeSections");

            migrationBuilder.DropTable(
                name: "ProcessTrees");

            migrationBuilder.DropTable(
                name: "ScreenShots");

            migrationBuilder.DropTable(
                name: "SignatureReferences");

            migrationBuilder.DropTable(
                name: "StaticKeys");

            migrationBuilder.DropTable(
                name: "StaticSignatures");

            migrationBuilder.DropTable(
                name: "TargetPids");

            migrationBuilder.DropTable(
                name: "TargetUrls");

            migrationBuilder.DropTable(
                name: "TCDomains");

            migrationBuilder.DropTable(
                name: "TCEmails");

            migrationBuilder.DropTable(
                name: "TCHashes");

            migrationBuilder.DropTable(
                name: "TCIps");

            migrationBuilder.DropTable(
                name: "TCReferences");

            migrationBuilder.DropTable(
                name: "TCResolutions");

            migrationBuilder.DropTable(
                name: "TCScans");

            migrationBuilder.DropTable(
                name: "TCSubdomanins");

            migrationBuilder.DropTable(
                name: "VirusTotalComments");

            migrationBuilder.DropTable(
                name: "VirusTotalScans");

            migrationBuilder.DropTable(
                name: "YaraDroppeds");

            migrationBuilder.DropTable(
                name: "AspNetRoles");

            migrationBuilder.DropTable(
                name: "PeExports");

            migrationBuilder.DropTable(
                name: "PeImports");

            migrationBuilder.DropTable(
                name: "MarkCalls");

            migrationBuilder.DropTable(
                name: "CuckooBehaviors");

            migrationBuilder.DropTable(
                name: "CuckooTargets");

            migrationBuilder.DropTable(
                name: "ThreatCrowdInfo");

            migrationBuilder.DropTable(
                name: "VirusTotalInfos");

            migrationBuilder.DropTable(
                name: "CuckooDroppeds");

            migrationBuilder.DropTable(
                name: "CuckooStatics");

            migrationBuilder.DropTable(
                name: "Marks");

            migrationBuilder.DropTable(
                name: "CuckooSignatures");

            migrationBuilder.DropTable(
                name: "CuckooInfos");

            migrationBuilder.DropTable(
                name: "Malwares");

            migrationBuilder.DropTable(
                name: "AspNetUsers");
        }
    }
}
