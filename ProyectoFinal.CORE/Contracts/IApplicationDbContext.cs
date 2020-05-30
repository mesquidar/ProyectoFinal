using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using ProyectoFinal.CORE.VirusTotal;
using ProyectoFinal.CORE.ThreatCrowd;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.CORE.Contracts
{
    public interface IApplicationDbContext
    {

        public DbSet<Comment> Comments { get; set; }
        public DbSet<Malware> Malwares { get; set; }
        public DbSet<ScreenShot> ScreenShots { get; set; }
        public DbSet<VirusTotalInfo> VirusTotalInfos { get; set; }
        public DbSet<VirusTotalComments> VirusTotalComments { get; set; }
        public DbSet<VirusTotalScans> VirusTotalScans { get; set; }
        public DbSet<ThreatCrowdInfo> ThreatCrowdInfo { get; set; }
        public DbSet<TCResolution> TCResolutions { get; set; }
        public DbSet<CuckooInfo> CuckooInfos { get; set; }
        public DbSet<CuckooTarget> CuckooTargets { get; set; }
        public DbSet<CuckooBehavior> CuckooBehaviors { get; set; }
        public DbSet<CuckooDropped> CuckooDroppeds { get; set; }
        public DbSet<CuckooSignature> CuckooSignatures { get; set; }
        public DbSet<CuckooStatic> CuckooStatics { get; set; }
        public DbSet<Exports> Exports { get; set; }
        public DbSet<Imports> Imports { get; set; }
        public DbSet<Mark> Marks { get; set; }
        public DbSet<MarkArguments> MarkArguments { get; set; }
        public DbSet<MarkCall> MarkCalls { get; set; }
        public DbSet<MarkSection> MarkSections { get; set; }
        public DbSet<PeExport> PeExports { get; set; }
        public DbSet<PeImport> PeImports { get; set; }
        public DbSet<PeResource> PeResources { get; set; }
        public DbSet<PeSection> PeSections { get; set; }
        public DbSet<ProcessTree> ProcessTrees { get; set; }
        public DbSet<StaticSignature> StaticSignatures { get; set; }
        public DbSet<YaraDropped> YaraDroppeds { get; set; }
        public DbSet<TCDomains> TCDomains { get; set; }
        public DbSet<TCEmails> TCEmails { get; set; }
        public DbSet<TCHashes> TCHashes { get; set; }
        public DbSet<TCIps> TCIps { get; set; }
        public DbSet<TCReferences> TCReferences { get; set; }
        public DbSet<TCScans> TCScans { get; set; }
        public DbSet<TCSubdomanins> TCSubdomanins { get; set; }
        public DbSet<DroppedPids> DroppedPids { get; set; }
        public DbSet<DroppedUrls> DroppedUrls { get; set; }
        public DbSet<TargetPids> TargetPids { get; set; }
        public DbSet<TargetUrls> TargetUrls { get; set; }
        public DbSet<BehaviorSummary> BehaviorSummaries { get; set; }
        public DbSet<StaticKeys> StaticKeys { get; set; }
        public DbSet<SignatureReferences> SignatureReferences { get; set; }

        EntityEntry Entry(object entity);

        EntityEntry<TEntity> Entry<TEntity>(TEntity entity) where TEntity : class;

        int SaveChanges();
        Task<int> SaveChangesAsync();


        //DbSet Set(Type entityType);

        DbSet<TEntity> Set<TEntity>() where TEntity : class;
    }
}