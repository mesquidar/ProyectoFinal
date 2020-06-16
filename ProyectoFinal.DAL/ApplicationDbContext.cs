using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.ThreatCrowd;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.DAL
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>, IApplicationDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        /// <summary>
        /// Metodo qe implement el guardado de cambios de forma asincrona
        /// </summary>
        /// <returns></returns>
        public Task<int> SaveChangesAsync() => base.SaveChangesAsync();

        /// <summary>
        /// Genera tabla comentarios
        /// </summary>
        public DbSet<Comment> Comments { get; set; }

        /// <summary>
        /// Genera tabla de malwares
        /// </summary>
        public DbSet<Malware> Malwares { get; set; }

        /// <summary>
        /// Genera tabla de screenshots
        /// </summary>
        public DbSet<ScreenShot> ScreenShots { get; set; }

        /// <summary>
        /// Genera tabla de virustotal
        /// </summary>
        public DbSet<VirusTotalInfo> VirusTotalInfos { get; set; }

        /// <summary>
        /// Genera tabla de productos de comnetarios de virustotal
        /// </summary>
        public DbSet<VirusTotalComments> VirusTotalComments { get; set; }

        /// <summary>
        /// Genera tabla de escaneos de virustotal
        /// </summary>
        public DbSet<VirusTotalScans> VirusTotalScans { get; set; }

        /// <summary>
        /// Genera tabla de threatcrowd
        /// </summary>
        public DbSet<ThreatCrowdInfo> ThreatCrowdInfo { get; set; }

        /// <summary>
        /// Genera tabla de threatcrowd resolutions
        /// </summary>
        public DbSet<TCResolution> TCResolutions { get; set; }

        /// <summary>
        /// Genera tabla CuckooInfos
        /// </summary>
        public DbSet<CuckooInfo> CuckooInfos { get; set; }

        /// <summary>
        /// Genera tabla CuckooTargets
        /// </summary>
        public DbSet<CuckooTarget> CuckooTargets { get; set; }

        /// <summary>
        /// Genera tabla CuckooStrings
        /// </summary>
        public DbSet<CuckooStrings> CuckooStrings { get; set; }

        /// <summary>
        /// Genera tabla de CuckooBehaviors
        /// </summary>
        public DbSet<CuckooBehavior> CuckooBehaviors { get; set; }

        /// <summary>
        /// Genera tabla de CuckooDroppeds
        /// </summary>
        public DbSet<CuckooDropped> CuckooDroppeds { get; set; }

        /// <summary>
        /// Genera tabla de CuckooSignatures
        /// </summary>
        public DbSet<CuckooSignature> CuckooSignatures { get; set; }

        /// <summary>
        /// Genera tabla de CuckooStatics
        /// </summary>
        public DbSet<CuckooStatic> CuckooStatics { get; set; }

        /// <summary>
        /// Genera tabla de Exports
        /// </summary>
        public DbSet<Exports> Exports { get; set; }

        /// <summary>
        /// Genera tabla de Imports
        /// </summary>
        public DbSet<Imports> Imports { get; set; }

        /// <summary>
        /// Genera tabla de Marks
        /// </summary>
        public DbSet<Mark> Marks { get; set; }

        /// <summary>
        /// Genera tabla MarkArguments
        /// </summary>
        public DbSet<MarkArguments> MarkArguments { get; set; }

        /// <summary>
        /// Genera tabla MarkCalls
        /// </summary>
        public DbSet<MarkCall> MarkCalls { get; set; }

        /// <summary>
        /// Genera tabla de MarkSections
        /// </summary>
        public DbSet<MarkSection> MarkSections { get; set; }

        /// <summary>
        /// Genera tabla de PeExports
        /// </summary>
        public DbSet<PeExport> PeExports { get; set; }

        /// <summary>
        /// Genera tabla de PeImports
        /// </summary>
        public DbSet<PeImport> PeImports { get; set; }

        /// <summary>
        /// Genera tabla de PeResources
        /// </summary>
        public DbSet<PeResource> PeResources { get; set; }

        /// <summary>
        /// Genera tabla de PeSection
        /// </summary>
        public DbSet<PeSection> PeSections { get; set; }

        /// <summary>
        /// Genera tabla de ProcessTree
        /// </summary>
        public DbSet<ProcessTree> ProcessTrees { get; set; }

        /// <summary>
        /// Genera tabla de StaticSigantures
        /// </summary>
        public DbSet<StaticSignature> StaticSignatures { get; set; }

        /// <summary>
        /// Genera tabla de yaradroppeds
        /// </summary>
        public DbSet<YaraDropped> YaraDroppeds { get; set; }

        /// <summary>
        /// Genera tabla de PeSection
        /// </summary>
        public DbSet<TCDomains> TCDomains { get; set; }

        /// <summary>
        /// Genera tabla de ProcessTree
        /// </summary>
        public DbSet<TCEmails> TCEmails { get; set; }

        /// <summary>
        /// Genera tabla de StaticSigantures
        /// </summary>
        public DbSet<TCHashes> TCHashes { get; set; }

        /// <summary>
        /// Genera tabla de yaradroppeds
        /// </summary>
        public DbSet<TCIps> TCIps { get; set; }

        /// <summary>
        /// Genera tabla de PeSection
        /// </summary>
        public DbSet<TCReferences> TCReferences { get; set; }

        /// <summary>
        /// Genera tabla de ProcessTree
        /// </summary>
        public DbSet<TCScans> TCScans { get; set; }

        /// <summary>
        /// Genera tabla de StaticSigantures
        /// </summary>
        public DbSet<TCSubdomanins> TCSubdomanins { get; set; }

        /// <summary>
        /// Genera tabla de yaradroppeds
        /// </summary>
        public DbSet<DroppedPids> DroppedPids { get; set; }

        /// <summary>
        /// Genera tabla de PeSection
        /// </summary>
        public DbSet<DroppedUrls> DroppedUrls { get; set; }

        /// <summary>
        /// Genera tabla de ProcessTree
        /// </summary>
        public DbSet<TargetPids> TargetPids { get; set; }

        /// <summary>
        /// Genera tabla de StaticSigantures
        /// </summary>
        public DbSet<TargetUrls> TargetUrls { get; set; }

        /// <summary>
        /// Genera tabla de yaradroppeds
        /// </summary>
        public DbSet<BehaviorSummary> BehaviorSummaries { get; set; }
        /// <summary>
        /// Genera tabla de PeSection
        /// </summary>
        public DbSet<StaticKeys> StaticKeys { get; set; }

        /// <summary>
        /// Genera tabla de ProcessTree
        /// </summary>
        public DbSet<SignatureReferences> SignatureReferences { get; set; }

    }
}
